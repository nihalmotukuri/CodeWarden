import sys
import argparse
from app.router import get_local_git_diff, run_codewarden


def main():
    parser = argparse.ArgumentParser(description="CodeWarden — Offline AI PR Security & Architecture Auditor")
    sub = parser.add_subparsers(dest="command", required=True)

    diff_cmd = sub.add_parser("diff", help="Audit uncommitted or staged Git changes in a local repo")
    diff_cmd.add_argument("--repo", default=".", help="Path to Git repository (default: current directory)")
    diff_cmd.add_argument("--staged", action="store_true", help="Audit only staged changes (git diff --cached)")

    file_cmd = sub.add_parser("file", help="Audit a single source code file")
    file_cmd.add_argument("path", help="Path to source code file")

    ask_cmd = sub.add_parser("ask", help="Auto-routed query or inline code snippet")
    ask_cmd.add_argument("prompt", help="Code snippet or engineering question")

    args = parser.parse_args()

    if args.command == "diff":
        diff_text = get_local_git_diff(repo_path=args.repo, staged_only=args.staged)
        if not diff_text:
            print("No uncommitted changes found to audit.")
            sys.exit(0)
        route, output, tps = run_codewarden(diff_text)
    elif args.command == "file":
        with open(args.path, "r", encoding="utf-8") as f:
            code = f.read()
        route, output, tps = run_codewarden(code, filename=args.path, force_audit=True)
    else:
        route, output, tps = run_codewarden(args.prompt)

    print(f"\n[CodeWarden Router] Mode: {route.mode} | Lang: {route.language} | Speed: {tps:.1f} tok/s")
    print("=" * 72)
    print(output)
    print("=" * 72)


if __name__ == "__main__":
    main()
