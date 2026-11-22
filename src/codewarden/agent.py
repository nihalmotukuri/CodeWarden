from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

import ollama
from pydantic import ValidationError

from codewarden.models import FunctionSlice, ReviewFinding, SliceReview
from codewarden.tools import TOOL_SCHEMAS, RepoToolbox

SYSTEM_PROMPT = """You are CodeWarden, a precision static-analysis and security/bug triage engine powered by Actuator-7B.

Your job is to inspect a modified function slice and its unified diff patch to detect concrete bugs, security vulnerabilities, broken state transitions, missing authorization checks, or edge-case crashes.

Tool Usage Rules:
1. The full source of the target function, its file imports, and the unified diff patch are ALREADY provided in the prompt. Do NOT call `read_file` on the same line range or `get_file_imports` on the target file itself.
2. Only call tools (`search_symbol`, `read_file` on other files or lines outside the slice, `get_file_imports` on imported files) to verify external functions, helpers, hooks, or callers—never search for local parameter names.
3. Emit distinct tool calls in parallel when verifying multiple external symbols; never emit duplicate calls.

Review Rules:
1. Actively check for high-impact defects in the changed lines and diff:
   - Injection vulnerabilities (e.g., SQL/command/HTML injection via f-strings, template literals, or string concatenation instead of parameterized queries).
   - Broken access control / IDOR (e.g., mutating or reading a resource by ID while ignoring `user_id` / `session_user_id` parameters or removing ownership checks).
   - Functional & state bugs (missing state resets, stale closures, race conditions, null/undefined dereferences, off-by-one bounds).
2. Category discipline: use `security` ONLY for actual vulnerabilities (injection, IDOR/auth bypass, XSS, open redirects, secret exposure). Use `bug` or `logic` for broken state updates, stale closures, missing resets, or crashes.
3. Frontend vs. Backend Context: In browser/client components (`'use client'`, React hooks, `fetch()`), standard HTTP headers like `Authorization: `Bearer ${token}`` are normal client auth—NEVER flag them as SQL/command injection or server-side IDORs. Client UI cannot perform server-side token ownership verification.
4. Never treat UI/animation state (such as `reducedMotion`, theme toggles, or layout flags) or external framework hooks as security/IDOR issues.
5. Abstain strictly when the code is sound: if the modified lines are safe and bug-free, do NOT invent stylistic suggestions or speculative nitpicks—return `has_issues: false` and `findings: []`.
"""


@dataclass
class AgentTrace:
    slice_review: SliceReview
    tool_calls: list[dict[str, Any]]


class CodeWardenAgent:
    """Tool-calling code review agent driven by Actuator-7B over Ollama."""

    def __init__(
        self,
        toolbox: RepoToolbox,
        model: str = "actuator-7b:latest",
        host: str = "http://localhost:11434",
        max_steps: int = 2,
        on_tool_call: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.toolbox = toolbox
        self.model = model
        self.client = ollama.Client(host=host)
        self.max_steps = max_steps
        self.on_tool_call = on_tool_call

    def _format_slice_prompt(self, fn_slice: FunctionSlice) -> str:
        numbered_lines = []
        for offset, line in enumerate(fn_slice.source_code.splitlines()):
            line_no = fn_slice.start_line + offset
            marker = ">" if line_no in fn_slice.changed_lines else " "
            numbered_lines.append(f"{marker} {line_no:4d} | {line}")

        imports_block = "\n".join(fn_slice.imports) if fn_slice.imports else "(none)"
        patch_block = fn_slice.raw_patch if fn_slice.raw_patch else "(no patch)"
        return (
            f"Target File: {fn_slice.file_path}\n"
            f"Enclosing Symbol: {fn_slice.symbol_name} ({fn_slice.node_type})\n"
            f"Provided Line Range: {fn_slice.start_line}-{fn_slice.end_line}\n"
            f"Modified/Anchored Lines (marked with '>'): {fn_slice.changed_lines}\n\n"
            f"Target File Imports (already loaded):\n{imports_block}\n\n"
            f"Unified Diff Patch:\n```diff\n{patch_block}\n```\n\n"
            f"Function Source (already loaded):\n```{fn_slice.language}\n"
            + "\n".join(numbered_lines)
            + "\n```\n\n"
            "Verify any external helpers or symbols if needed using your tools, then produce the structured SliceReview."
        )

    def review_slice(self, fn_slice: FunctionSlice) -> AgentTrace:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": self._format_slice_prompt(fn_slice)},
        ]
        recorded_calls: list[dict[str, Any]] = []
        seen_in_slice: set[str] = set()

        for _step in range(self.max_steps):
            response = self.client.chat(
                model=self.model,
                messages=messages,
                tools=TOOL_SCHEMAS,
                options={"temperature": 0.0, "num_predict": 1024, "num_ctx": 8192},
            )
            assistant_msg = response.message
            tool_calls = assistant_msg.tool_calls or []

            if not tool_calls:
                raw_text = (assistant_msg.content or "").strip()
                parsed = self._try_parse_review(raw_text, fn_slice)
                if parsed is not None:
                    return AgentTrace(slice_review=parsed, tool_calls=recorded_calls)
                messages.append({"role": "assistant", "content": raw_text})
                break

            messages.append(assistant_msg.model_dump(exclude_none=True))

            for call in tool_calls:
                fn_name = call.function.name
                raw_args = call.function.arguments
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                sig = f"{fn_name}:{json.dumps(args, sort_keys=True)}"

                observation, _cached = self.toolbox.dispatch(fn_name, args)
                if sig not in seen_in_slice:
                    seen_in_slice.add(sig)
                    recorded_calls.append({"tool": fn_name, "arguments": args})
                    if self.on_tool_call:
                        self.on_tool_call(fn_name, args)

                messages.append(
                    {
                        "role": "tool",
                        "tool_name": fn_name,
                        "content": observation,
                    }
                )

        messages.append(
            {
                "role": "user",
                "content": (
                    "Based on the Unified Diff Patch, Function Source, and tool results above, "
                    "audit the modified lines for any security vulnerabilities (such as SQL/command injection "
                    "or missing user authorization checks) or logic/state bugs, and output the SliceReview JSON."
                ),
            }
        )
        final_response = self.client.chat(
            model=self.model,
            messages=messages,
            format=SliceReview.model_json_schema(),
            options={"temperature": 0.0, "num_predict": 1024, "num_ctx": 8192},
        )
        final_text = (final_response.message.content or "").strip()
        parsed = self._try_parse_review(final_text, fn_slice)
        if parsed is None:
            parsed = SliceReview(
                has_issues=False,
                findings=[],
                summary="No actionable defects identified.",
            )
        return AgentTrace(slice_review=parsed, tool_calls=recorded_calls)

    @staticmethod
    def _try_parse_review(raw_text: str, fn_slice: FunctionSlice) -> SliceReview | None:
        if not raw_text:
            return None
        try:
            review = SliceReview.model_validate_json(raw_text)
        except ValidationError:
            return None

        cleaned: list[ReviewFinding] = []
        for item in review.findings:
            if item.confidence < 0.65:
                continue
            item.file_path = item.file_path or fn_slice.file_path
            item.symbol_name = item.symbol_name or fn_slice.symbol_name
            cleaned.append(item)

        return SliceReview(
            has_issues=bool(cleaned),
            findings=cleaned,
            summary=review.summary,
        )

    def generate_patch(self, fn_slice: FunctionSlice, finding: ReviewFinding) -> tuple[str, str]:
        schema = {"type": "object", "properties": {"original_code": {"type": "string", "minLength": 1}, "replacement_code": {"type": "string", "minLength": 1}}, "required": ["original_code", "replacement_code"]}
        try:
            resp = self.client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Return JSON with ONLY the 1-3 exact defective lines in `original_code` and fixed lines in `replacement_code`. Never copy the whole function."},
                    {"role": "user", "content": f"Line {finding.line}: {finding.title} ({finding.suggested_fix})\nCode:\n{fn_slice.source_code}"},
                ],
                format=schema,
                options={"temperature": 0.0, "num_predict": 1024},
            )
            data = json.loads(resp.message.content)
            return data.get("original_code", ""), data.get("replacement_code", "")
        except Exception:
            return "", ""
