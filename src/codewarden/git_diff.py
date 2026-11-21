from __future__ import annotations

import re
import subprocess
from pathlib import Path

from codewarden.models import DiffHunk

HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def get_git_diff(repo_path: Path, base_ref: str | None = None, staged: bool = False) -> str:
    cmd = ["git", "-C", str(repo_path), "diff", "--unified=3"]
    if base_ref:
        cmd.append(f"{base_ref}...HEAD")
    elif staged:
        cmd.append("--cached")

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff failed: {proc.stderr.strip()}")
    return proc.stdout


def parse_unified_diff(diff_text: str) -> list[DiffHunk]:
    hunks_by_file: dict[str, DiffHunk] = {}
    current_file: str | None = None
    new_line_num = 0
    old_line_num = 0
    in_hunk = False
    patch_lines: list[str] = []

    def _flush_patch() -> None:
        nonlocal patch_lines
        if current_file and patch_lines and current_file in hunks_by_file:
            existing = hunks_by_file[current_file].raw_patch
            joined = "\n".join(patch_lines)
            hunks_by_file[current_file].raw_patch = f"{existing}\n{joined}".strip()
        patch_lines = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            _flush_patch()
            in_hunk = False
            current_file = None
            continue

        if line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                current_file = None
            else:
                current_file = target[2:] if target.startswith("b/") else target
                if current_file not in hunks_by_file:
                    hunks_by_file[current_file] = DiffHunk(file_path=current_file)
            continue

        if line.startswith("--- "):
            continue

        match = HUNK_HEADER_RE.match(line)
        if match and current_file:
            _flush_patch()
            in_hunk = True
            old_line_num = int(match.group(1))
            new_line_num = int(match.group(3))
            patch_lines.append(line)
            continue

        if in_hunk and current_file:
            patch_lines.append(line)
            if line.startswith("+") and not line.startswith("+++"):
                hunks_by_file[current_file].added_lines.append(new_line_num)
                new_line_num += 1
            elif line.startswith("-") and not line.startswith("---"):
                hunks_by_file[current_file].removed_lines.append(old_line_num)
                hunks_by_file[current_file].deletion_anchors.append(max(1, new_line_num))
                old_line_num += 1
            else:
                old_line_num += 1
                new_line_num += 1

    _flush_patch()
    return [h for h in hunks_by_file.values() if h.added_lines or h.removed_lines]
