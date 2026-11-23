from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codewarden.agent import CodeWardenAgent
from codewarden.ast_slicer import slice_hunk
from codewarden.git_diff import get_git_diff, parse_unified_diff
from codewarden.tools import RepoToolbox


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def test_toolbox_sandbox_and_builtin_filter(tmp_path: Path) -> None:
    sample = tmp_path / "app.py"
    sample.write_text("def greet(name: str) -> str:\n    return f'hi {name}'\n", encoding="utf-8")

    tb = RepoToolbox(tmp_path)

    # Path traversal must be blocked
    out, _ = tb.dispatch("read_file", {"path": "../../etc/passwd", "start_line": 1, "end_line": 5})
    assert "Path traversal blocked" in out

    # Builtin short-circuit
    builtin_out, _ = tb.dispatch("search_symbol", {"query": "useState"})
    assert "standard runtime builtin" in builtin_out

    # Deduplication cache hit on second identical call
    first_out, cached_1 = tb.dispatch("search_symbol", {"query": "greet"})
    second_out, cached_2 = tb.dispatch("search_symbol", {"query": "greet"})
    assert "app.py:1:" in first_out
    assert cached_1 is False
    assert cached_2 is True
    assert first_out == second_out


def test_ast_slicer_extracts_enclosing_python_function(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")

    api_file = tmp_path / "notes_api.py"
    api_file.write_text(
        "from db import fetch_note\n\n"
        "def get_note(note_id: str, current_user_id: str):\n"
        "    note = fetch_note(note_id)\n"
        "    if note.owner_id != current_user_id:\n"
        "        raise PermissionError('Forbidden')\n"
        "    return note\n",
        encoding="utf-8",
    )
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "initial")

    # Introduce an IDOR vulnerability by removing the ownership check
    api_file.write_text(
        "from db import fetch_note\n\n"
        "def get_note(note_id: str, current_user_id: str):\n"
        "    note = fetch_note(note_id)\n"
        "    return note\n",
        encoding="utf-8",
    )

    diff = get_git_diff(tmp_path)
    hunks = parse_unified_diff(diff)
    assert len(hunks) == 1

    slices = slice_hunk(tmp_path, hunks[0])
    assert len(slices) == 1
    assert slices[0].symbol_name == "get_note"
    assert slices[0].start_line == 3
    assert slices[0].end_line == 5


@pytest.mark.integration
def test_actuator_catches_real_idor_and_sql_injection(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")

    (tmp_path / "db.py").write_text(
        "class Note:\n"
        "    id: str\n"
        "    owner_id: str\n"
        "    content: str\n\n"
        "def delete_note_by_id(cursor, note_id: str) -> None:\n"
        "    cursor.execute('DELETE FROM notes WHERE id = ?', (note_id,))\n",
        encoding="utf-8",
    )
    handler = tmp_path / "routes.py"
    handler.write_text(
        "from db import delete_note_by_id\n\n"
        "def handle_delete_note(cursor, note_id: str, session_user_id: str) -> dict:\n"
        "    delete_note_by_id(cursor, note_id)\n"
        "    return {'deleted': note_id}\n",
        encoding="utf-8",
    )
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "initial")

    # Modify handler to construct raw SQL string AND skip session_user_id authorization
    handler.write_text(
        "from db import delete_note_by_id\n\n"
        "def handle_delete_note(cursor, note_id: str, session_user_id: str) -> dict:\n"
        "    cursor.execute(f\"DELETE FROM notes WHERE id = '{note_id}'\")\n"
        "    return {'deleted': note_id}\n",
        encoding="utf-8",
    )

    diff = get_git_diff(tmp_path)
    slices = slice_hunk(tmp_path, parse_unified_diff(diff)[0])
    tb = RepoToolbox(tmp_path)
    agent = CodeWardenAgent(toolbox=tb, model="actuator-7b:latest")
    trace = agent.review_slice(slices[0])

    assert trace.slice_review.has_issues is True
    assert len(trace.slice_review.findings) >= 1
    assert any(f.severity in {"critical", "high"} for f in trace.slice_review.findings)


def test_v020_init_and_cross_file_tools(tmp_path: Path) -> None:
    import subprocess
    from typer.testing import CliRunner
    from codewarden.cli import app, _check_syntax
    from codewarden.tools import RepoToolbox

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, check=True)
    f = tmp_path / "svc.py"
    f.write_text("def run_query(sql):\n    return sql\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=tmp_path, check=True)

    res = CliRunner().invoke(app, ["init", "--repo", str(tmp_path)])
    assert res.exit_code == 0
    assert (tmp_path / ".git" / "hooks" / "pre-commit").is_file()
    assert (tmp_path / ".github" / "workflows" / "codewarden.yml").is_file()

    tb = RepoToolbox(tmp_path)
    refs, _ = tb.dispatch("find_references", {"symbol": "run_query"})
    assert "svc.py:1" in refs
    blame, _ = tb.dispatch("git_blame", {"path": "svc.py", "start_line": 1, "end_line": 2})
    assert "def run_query" in blame

    bad = tmp_path / "bad.py"
    bad.write_text("def broken(:\n    pass\n")
    syn = _check_syntax(tmp_path, "bad.py")
    assert syn is not None and syn.title == "Python Syntax Error"
