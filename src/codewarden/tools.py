from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".turbo",
    "coverage",
}

IGNORED_BUILTINS = {
    # React / Framer Motion / Browser builtins
    "useState",
    "useEffect",
    "useRef",
    "useMemo",
    "useCallback",
    "useContext",
    "useReducer",
    "useId",
    "useLayoutEffect",
    "Fragment",
    "Suspense",
    "StrictMode",
    "createContext",
    "forwardRef",
    "memo",
    "motion",
    "AnimatePresence",
    "useSpring",
    "useTransform",
    "useScroll",
    "useMotionValue",
    "useReducedMotion",
    "useNavigate",
    "useLocation",
    "useParams",
    "Navigate",
    "Link",
    "Array.from",
    "Promise.all",
    "JSON.parse",
    "JSON.stringify",
    "Object.keys",
    "Object.values",
    "Object.entries",
    "console.log",
    "console.error",
    "setTimeout",
    "clearTimeout",
    "setInterval",
    "clearInterval",
    # Python builtins
    "len",
    "str",
    "int",
    "float",
    "bool",
    "dict",
    "list",
    "set",
    "tuple",
    "print",
    "isinstance",
    "enumerate",
    "zip",
    "range",
}


class RepoToolbox:
    """Sandboxed, cached read-only repository tools exposed to Actuator-7B."""

    def __init__(self, repo_path: str | Path) -> None:
        self.repo_root = Path(repo_path).expanduser().resolve()
        if not self.repo_root.is_dir():
            raise ValueError(f"Repository path does not exist: {self.repo_root}")
        self._cache: dict[str, str] = {}

    def _resolve_safe_path(self, rel_path: str) -> Path:
        clean_rel = rel_path.lstrip("/")
        candidate = (self.repo_root / clean_rel).resolve()
        if candidate != self.repo_root and self.repo_root not in candidate.parents:
            raise ValueError(f"Path traversal blocked: {rel_path}")
        return candidate

    def read_file(self, path: str, start_line: int = 1, end_line: int = 120) -> str:
        """Read a line-numbered window from a file inside the repository."""
        target = self._resolve_safe_path(path)
        if not target.is_file():
            return f"Error: File '{path}' not found."

        start = max(1, int(start_line))
        end = max(start, min(int(end_line), start + 250))

        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        total = len(lines)
        if start > total:
            return f"File '{path}' only has {total} lines."

        slice_lines = lines[start - 1 : end]
        numbered = [f"{idx:4d} | {line}" for idx, line in enumerate(slice_lines, start=start)]
        return f"File: {path} (lines {start}-{min(end, total)} of {total})\n" + "\n".join(numbered)

    def get_file_imports(self, path: str) -> str:
        """Return import/export lines and top-of-file declarations for quick dependency context."""
        target = self._resolve_safe_path(path)
        if not target.is_file():
            return f"Error: File '{path}' not found."

        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        import_lines = [
            f"{idx:4d} | {line}"
            for idx, line in enumerate(lines[:80], start=1)
            if line.lstrip().startswith(("import ", "from ", "export ", "type ", "interface "))
        ]
        if not import_lines:
            return f"No top-level imports or type declarations found in '{path}'."
        return f"Top imports/types in {path}:\n" + "\n".join(import_lines[:35])

    def search_symbol(self, query: str, file_glob: str | None = None, max_results: int = 25) -> str:
        """Search for a symbol, hook, type, or function name across the repository."""
        q = query.strip()
        if not q:
            return "Error: Search query cannot be empty."
        if q in IGNORED_BUILTINS or len(q) <= 2:
            return f"'{q}' is a standard runtime builtin/short token; no repository lookup needed."

        limit = max(1, min(int(max_results), 40))
        cmd = ["git", "-C", str(self.repo_root), "grep", "-n", "-I", "--fixed-strings", q]
        if file_glob:
            cmd.extend(["--", file_glob])

        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            matches = proc.stdout.strip().splitlines()
            shown = matches[:limit]
            suffix = f"\n... ({len(matches) - limit} more matches truncated)" if len(matches) > limit else ""
            return "\n".join(shown) + suffix

        results: list[str] = []
        for file_path in self.repo_root.rglob("*"):
            if any(part in SKIP_DIRS for part in file_path.parts) or not file_path.is_file():
                continue
            if file_glob and not file_path.match(file_glob):
                continue
            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            rel = file_path.relative_to(self.repo_root).as_posix()
            for idx, line in enumerate(content.splitlines(), start=1):
                if q in line:
                    results.append(f"{rel}:{idx}:{line.strip()}")
                    if len(results) >= limit:
                        return "\n".join(results)

        return "\n".join(results) if results else f"No matches found for '{query}'."

    def dispatch(self, tool_name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        """Execute a tool call with deduplication caching. Returns (output, was_cached)."""
        cache_key = f"{tool_name}:{json.dumps(arguments, sort_keys=True)}"
        if cache_key in self._cache:
            return self._cache[cache_key], True

        handlers = {
            "read_file": self.read_file,
            "get_file_imports": self.get_file_imports,
            "search_symbol": self.search_symbol,
        }
        handler = handlers.get(tool_name)
        if handler is None:
            return f"Error: Unknown tool '{tool_name}'.", False
        try:
            result = handler(**arguments)
        except TypeError as exc:
            result = f"Error: Invalid arguments for '{tool_name}': {exc}"
        except ValueError as exc:
            result = f"Error: {exc}"

        self._cache[cache_key] = result
        return result, False


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read lines OUTSIDE the provided Function Source (e.g., top-of-file constants, helper functions, or another component file). Do NOT re-read line ranges already included in Function Source.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path from the repository root.",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "1-based start line number.",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "1-based end line number (max 250 lines per call).",
                    },
                },
                "required": ["path", "start_line", "end_line"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_file_imports",
            "description": "Read top-level imports, types, and interfaces from another file in the repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path from the repository root.",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_symbol",
            "description": "Search for a project-defined function, hook, type, constant, or component across the codebase. Do NOT search for standard React hooks or JS/Python builtins.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Project symbol or identifier name to search for.",
                    },
                    "file_glob": {
                        "type": "string",
                        "description": "Optional glob pattern to restrict search (e.g. '*.tsx').",
                    },
                },
                "required": ["query"],
            },
        },
    },
]
