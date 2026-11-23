from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from codewarden.agent import CodeWardenAgent
from codewarden.ast_slicer import slice_hunk
from codewarden.git_diff import get_git_diff, parse_unified_diff
from codewarden.models import FunctionSlice, ReviewFinding, ReviewReport
from codewarden.tools import RepoToolbox

app = typer.Typer(name="codewarden", help="Local AI-powered security & bug triage engine.", no_args_is_help=True)
console = Console()

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}


@app.callback()
def main() -> None:
    """CodeWarden CLI."""


def _collect_slices(repo_path: Path, base: str | None, staged: bool) -> list[FunctionSlice]:
    diff_text = get_git_diff(repo_path, base_ref=base, staged=staged)
    hunks = parse_unified_diff(diff_text)
    slices: list[FunctionSlice] = []
    for hunk in hunks:
        slices.extend(slice_hunk(repo_path, hunk))
    return slices




def _check_syntax(repo_path: Path, rel_path: str) -> ReviewFinding | None:
    target = (repo_path / rel_path).resolve()
    if not target.is_file():
        return None
    if target.suffix == ".py":
        try:
            __import__("ast").parse(target.read_text(encoding="utf-8"), filename=rel_path)
        except SyntaxError as e:
            return ReviewFinding(file_path=rel_path, line=e.lineno or 1, symbol_name="<module>", severity="high", category="bug", confidence=1.0, title="Python Syntax Error", explanation=e.msg, suggested_fix="Fix the syntax error at the indicated line.")
    elif target.suffix in {".js", ".mjs", ".cjs"} and __import__("shutil").which("node"):
        res = __import__("subprocess").run(["node", "--check", str(target)], capture_output=True, text=True)
        if res.returncode != 0:
            lines = [ln for ln in res.stderr.splitlines() if ln.strip()]
            ln_no = next((int(l.split(":")[-1]) for l in lines if f"{target.name}:" in l and l.split(":")[-1].isdigit()), 1)
            return ReviewFinding(file_path=rel_path, line=ln_no, symbol_name="<module>", severity="high", category="bug", confidence=1.0, title="JavaScript Syntax Error", explanation=lines[-1] if lines else "Invalid JS syntax", suggested_fix="Fix the syntax error at the indicated line.")
    return None


def _apply_interactive_fix(repo_path: Path, finding: ReviewFinding) -> bool:
    """Preview an exact before/after patch and apply it upon user confirmation."""
    orig = finding.original_code.strip("\n")
    repl = finding.replacement_code.strip("\n")
    if not orig.strip() or not repl.strip() or orig.strip() == repl.strip():
        console.print(
            f"[yellow]Skipping auto-patch for {finding.file_path}:{finding.line} (no concrete replacement emitted).[/yellow]"
        )
        return False

    target = (repo_path / finding.file_path).resolve()
    if not target.is_file():
        return False

    content = target.read_text(encoding="utf-8")
    if content.count(orig) != 1:
        # Fallback: match stripped line while preserving original indentation
        matched_lines = [ln for ln in content.splitlines() if ln.strip() == orig.strip()]
        if len(matched_lines) == 1:
            indent = matched_lines[0][: len(matched_lines[0]) - len(matched_lines[0].lstrip())]
            orig = matched_lines[0]
            repl = "\n".join(indent + l.lstrip() if l.strip() else l for l in repl.splitlines())
        else:
            console.print(
                f"[yellow]Skipping auto-patch for {finding.file_path} (matched {content.count(orig)} locations).[/yellow]"
            )
            return False

    console.print(
        Panel(
            Syntax(
                f"- {orig}\n+ {repl}",
                "diff",
                theme="monokai",
                word_wrap=True,
            ),
            title=f"[bold cyan]Proposed Patch: {finding.file_path}:{finding.line}[/bold cyan]",
            border_style="cyan",
        )
    )
    if typer.confirm("Apply this fix to disk?", default=False):
        target.write_text(content.replace(orig, repl, 1), encoding="utf-8")
        console.print(f"[bold green]✓ Patched {finding.file_path}[/bold green]")
        return True
    return False


@app.command("slice")
def slice_changes(
    repo: Path = typer.Option(Path("."), "--repo", "-r", help="Path to target Git repository."),
    base: str | None = typer.Option(None, "--base", "-b", help="Base Git ref (e.g. main)."),
    staged: bool = typer.Option(False, "--staged", "-s", help="Inspect staged changes only."),
) -> None:
    """Extract full enclosing AST function slices for modified lines in a Git diff."""
    repo_path = repo.resolve()
    slices = _collect_slices(repo_path, base=base, staged=staged)

    if not slices:
        console.print("[yellow]No modified AST function slices detected in diff.[/yellow]")
        raise typer.Exit(code=0)

    files_seen = {s.file_path for s in slices}
    for fn in slices:
        header = (
            f"[bold cyan]{fn.file_path}[/bold cyan] :: "
            f"[bold green]{fn.symbol_name}[/bold green] "
            f"(lines {fn.start_line}-{fn.end_line}, changed: {fn.changed_lines})"
        )
        syntax = Syntax(
            fn.source_code,
            fn.language if fn.language != "tsx" else "typescript",
            line_numbers=True,
            start_line=fn.start_line,
            highlight_lines=set(fn.changed_lines),
            theme="monokai",
        )
        console.print(Panel(syntax, title=header, border_style="bright_blue"))

    console.print(f"[bold green]Extracted {len(slices)} function slice(s) across {len(files_seen)} file(s).[/bold green]")


@app.command("review")
def review_changes(
    repo: Path = typer.Option(Path("."), "--repo", "-r", help="Path to target Git repository."),
    base: str | None = typer.Option(None, "--base", "-b", help="Base Git ref (e.g. HEAD~1 or main)."),
    staged: bool = typer.Option(False, "--staged", "-s", help="Review staged changes only."),
    model: str = typer.Option("actuator-7b:latest", "--model", "-m", help="Local Ollama model name."),
    host: str = typer.Option("http://localhost:11434", "--host", help="Ollama server URL."),
    min_severity: str = typer.Option("medium", "--min-severity", help="Minimum severity to display (low|medium|high|critical)."),
    json_out: Path | None = typer.Option(None, "--json-out", help="Write structured JSON report to path."),
    fix: bool = typer.Option(False, "--fix", help="Interactively preview and apply suggested patches to disk."),
) -> None:
    """Run Actuator-7B tool-calling security & bug review on modified AST slices."""
    repo_path = repo.expanduser().resolve()
    min_rank = SEVERITY_RANK.get(min_severity.lower(), 2)
    slices = _collect_slices(repo_path, base=base, staged=staged)

    if not slices:
        console.print("[yellow]No modified AST function slices detected in diff.[/yellow]")
        raise typer.Exit(code=0)

    toolbox = RepoToolbox(repo_path)
    all_findings: list[ReviewFinding] = []
    slice_map: dict[int, FunctionSlice] = {}
    total_tool_calls = 0
    for fpath in {s.file_path for s in slices}:
        if syn := _check_syntax(repo_path, fpath):
            all_findings.append(syn)

    console.print(
        f"[bold cyan]CodeWarden[/bold cyan] analyzing [bold]{len(slices)}[/bold] AST slice(s) "
        f"with [bold green]{model}[/bold green]...\n"
    )

    for idx, fn in enumerate(slices, start=1):
        label = f"{fn.file_path}::{fn.symbol_name}"
        console.print(f"[dim][{idx}/{len(slices)}][/dim] Inspecting [bold]{label}[/bold] (lines {fn.start_line}-{fn.end_line})")

        def log_tool(tool_name: str, args: dict[str, object]) -> None:
            formatted_args = ", ".join(f"{k}={v!r}" for k, v in args.items())
            console.print(f"   [magenta]↳ tool[/magenta] [bold]{tool_name}[/bold]({formatted_args})")

        agent = CodeWardenAgent(toolbox=toolbox, model=model, host=host, on_tool_call=log_tool)
        trace = agent.review_slice(fn)
        total_tool_calls += len(trace.tool_calls)

        filtered = [
            f for f in trace.slice_review.findings
            if SEVERITY_RANK.get(f.severity, 0) >= min_rank
            and (not fn.changed_lines or any(abs(f.line - cl) <= 3 for cl in fn.changed_lines))
        ]

        if filtered:
            for f in filtered:
                slice_map[id(f)] = fn
            all_findings.extend(filtered)
            console.print(f"   [bold red]✗ {len(filtered)} issue(s) flagged[/bold red]")
        else:
            console.print(f"   [green]✓ Clean[/green] [dim]({trace.slice_review.summary})[/dim]")

    console.print()
    if not all_findings:
        console.print(
            Panel(
                f"Analyzed {len(slices)} slice(s) using {total_tool_calls} tool call(s). No defects at >= {min_severity} severity.",
                title="[bold green]CodeWarden Audit Passed[/bold green]",
                border_style="green",
            )
        )
    else:
        for finding in all_findings:
            sev_style = SEVERITY_COLORS.get(finding.severity, "white")
            body = (
                f"[bold]Location:[/bold] {finding.file_path}:{finding.line} in [cyan]{finding.symbol_name}[/cyan]\n"
                f"[bold]Category:[/bold] {finding.category}  |  [bold]Confidence:[/bold] {finding.confidence:.0%}\n\n"
                f"{finding.explanation}\n\n"
                f"[bold green]Suggested Fix:[/bold green]\n{finding.suggested_fix}"
            )
            console.print(
                Panel(
                    body,
                    title=f"[{sev_style}][{finding.severity.upper()}][/{sev_style}] {finding.title}",
                    border_style="red" if finding.severity in {"critical", "high"} else "yellow",
                )
            )
            if fix:
                if not finding.original_code.strip() and id(finding) in slice_map:
                    finding.original_code, finding.replacement_code = agent.generate_patch(slice_map[id(finding)], finding)
                _apply_interactive_fix(repo_path, finding)

        summary_table = Table(title="Audit Summary")
        summary_table.add_column("Slices Analyzed", justify="right")
        summary_table.add_column("Tool Calls", justify="right")
        summary_table.add_column("Total Findings", justify="right")
        summary_table.add_row(str(len(slices)), str(total_tool_calls), str(len(all_findings)))
        console.print(summary_table)

    if all_findings:
        raise typer.Exit(code=1)

    if json_out is not None:
        report = ReviewReport(
            repo=str(repo_path),
            model=model,
            slices_analyzed=len(slices),
            tool_calls_made=total_tool_calls,
            findings=all_findings,
        )
        json_out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[dim]Saved JSON report to {json_out}[/dim]")



@app.command("init")
def init_repo(
    repo: Path = typer.Option(Path("."), "--repo", "-r", help="Target Git repository."),
    hook: bool = typer.Option(True, "--hook/--no-hook", help="Install .git/hooks/pre-commit."),
    ci: bool = typer.Option(True, "--ci/--no-ci", help="Generate .github/workflows/codewarden.yml."),
) -> None:
    """Install a Git pre-commit hook and/or GitHub Actions workflow."""
    root = repo.resolve()
    if hook and (root / ".git").is_dir():
        hp = root / ".git" / "hooks" / "pre-commit"
        hp.write_text("#!/usr/bin/env bash\nset -e\nif ! command -v codewarden >/dev/null 2>&1; then exit 0; fi\ncodewarden review --staged --min-severity high\n")
        hp.chmod(0o755)
        console.print(f"[green]✓ Installed pre-commit hook at {hp}[/green]")
    if ci:
        wf = root / ".github" / "workflows" / "codewarden.yml"
        wf.parent.mkdir(parents=True, exist_ok=True)
        wf.write_text("name: CodeWarden Audit\non: [pull_request]\njobs:\n  audit:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n      - uses: astral-sh/setup-uv@v4\n      - run: uv tool install git+https://github.com/nihalmotukuri/CodeWarden.git\n      - run: codewarden review --base ${{ github.event.pull_request.base.sha }} --min-severity high --json-out codewarden-report.json\n")
        console.print(f"[green]✓ Generated CI workflow at {wf}[/green]")


if __name__ == "__main__":
    app()
