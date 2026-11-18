import re
import subprocess
from dataclasses import dataclass
from typing import Optional
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "codewarden:7b"

AUDIT_SYSTEM_PROMPT = (
    "You are CodeWarden, a strict Staff Application Security & Architecture Auditor. "
    "Analyze the provided code or Git diff and respond strictly using the CodeWarden Audit Schema. "
    "Do not include conversational filler."
)

CHAT_SYSTEM_PROMPT = (
    "You are CodeWarden, a senior full-stack and security-minded software engineer. "
    "Provide clear, secure, production-ready coding guidance."
)

EXT_LANG_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".cpp": "c++",
    ".cc": "c++",
    ".c": "c++",
    ".php": "php",
    ".cs": "c#",
}


@dataclass
class RouteResult:
    mode: str          # "AUDIT_DIFF" | "AUDIT_CODE" | "CHAT"
    language: str
    system_prompt: str
    formatted_prompt: str


def detect_language(text: str, filename: Optional[str] = None) -> str:
    if filename:
        for ext, lang in EXT_LANG_MAP.items():
            if filename.lower().endswith(ext):
                return lang

    # Check diff file headers (e.g. +++ b/app/main.py)
    diff_file_match = re.search(r"\+\+\+ b/[^\s]+(\.[a-zA-Z0-9]+)", text)
    if diff_file_match:
        ext = diff_file_match.group(1).lower()
        if ext in EXT_LANG_MAP:
            return EXT_LANG_MAP[ext]

    # Heuristic syntax detection
    t = text.lower()
    if "def " in t or "import " in t and ("fastapi" in t or "sqlite3" in t or "os." in t or "__name__" in t):
        return "python"
    if "const " in t or "async (" in t or "req." in t or "express" in t or "=>" in t:
        return "typescript" if ": string" in t or ": number" in t or "interface " in t else "javascript"
    if "public class " in t or "system.out." in t or "preparedstatement" in t:
        return "java"
    if "func " in t and "package " in t:
        return "go"
    if "#include" in t or "std::" in t:
        return "c++"
    if "<?php" in t or "$_get" in t or "$_post" in t:
        return "php"
    return "python"


def is_diff(text: str) -> bool:
    return bool(re.search(r"(^diff --git|^--- a/|^\+\+\+ b/|^@@ -\d+,\d+ \+\d+,\d+ @@)", text, re.MULTILINE))


def is_code_snippet(text: str) -> bool:
    code_signals = [
        r"```",
        r"\b(def|class|function|const|let|var|import|from|SELECT|INSERT|UPDATE|DELETE|public|private|func|#include)\b",
        r"[{};()=<>]{2,}",
        r"->|=>|::",
    ]
    score = sum(1 for pat in code_signals if re.search(pat, text))
    return score >= 2 or len(text.splitlines()) >= 5 and score >= 1


def route_input(user_input: str, filename: Optional[str] = None, force_audit: bool = False) -> RouteResult:
    cleaned = user_input.strip()
    lang = detect_language(cleaned, filename=filename)

    if is_diff(cleaned):
        prompt = cleaned if cleaned.startswith("AUDIT_DIFF") else f"AUDIT_DIFF ({lang}):\n```diff\n{cleaned}\n```"
        return RouteResult(
            mode="AUDIT_DIFF",
            language=lang,
            system_prompt=AUDIT_SYSTEM_PROMPT,
            formatted_prompt=prompt,
        )

    if force_audit or filename is not None or is_code_snippet(cleaned):
        if cleaned.startswith("AUDIT_CODE"):
            prompt = cleaned
        elif "```" in cleaned:
            prompt = f"AUDIT_CODE ({lang}):\n{cleaned}"
        else:
            prompt = f"AUDIT_CODE ({lang}):\n```{lang}\n{cleaned}\n```"
        return RouteResult(
            mode="AUDIT_CODE",
            language=lang,
            system_prompt=AUDIT_SYSTEM_PROMPT,
            formatted_prompt=prompt,
        )

    return RouteResult(
        mode="CHAT",
        language="general",
        system_prompt=CHAT_SYSTEM_PROMPT,
        formatted_prompt=cleaned,
    )


def get_local_git_diff(repo_path: str = ".", staged_only: bool = False) -> str:
    cmd = ["git", "-C", repo_path, "diff"]
    if staged_only:
        cmd.append("--cached")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or "Not a valid Git repository.")
    return res.stdout.strip()


def run_codewarden(user_input: str, filename: Optional[str] = None, force_audit: bool = False) -> tuple[RouteResult, str, float]:
    route = route_input(user_input, filename=filename, force_audit=force_audit)
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": route.system_prompt},
            {"role": "user", "content": route.formatted_prompt},
        ],
        "stream": False,
    }
    resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
    resp.raise_for_status()
    data = resp.json()

    content = data["message"]["content"]
    # Calculate tokens/sec directly from Ollama's nanosecond telemetry
    eval_count = data.get("eval_count", 0)
    eval_duration_ns = data.get("eval_duration", 1)
    tok_per_sec = eval_count / (eval_duration_ns / 1e9) if eval_duration_ns > 0 else 0.0
    return route, content, tok_per_sec
