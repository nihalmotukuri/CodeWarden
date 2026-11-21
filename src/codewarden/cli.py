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
    total_tool_calls = 0

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
        ]

        if filtered:
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

        summary_table = Table(title="Audit Summary")
        summary_table.add_column("Slices Analyzed", justify="right")
        summary_table.add_column("Tool Calls", justify="right")
        summary_table.add_column("Total Findings", justify="right")
        summary_table.add_row(str(len(slices)), str(total_tool_calls), str(len(all_findings)))
        console.print(summary_table)

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


if __name__ == "__main__":
    app()
