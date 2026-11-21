# CodeWarden

**Local, AST-aware security and bug triage engine powered by [Actuator-7B](https://huggingface.co/nihalmotukuri/actuator-7b-gguf).**

CodeWarden extracts the exact enclosing functions and components modified in a Git diff using **Tree-sitter**, equips **Actuator-7B** (running locally via Ollama) with sandboxed read-only repository tools, and outputs schema-validated bug and security reports—with zero cloud API calls.

## Why CodeWarden?

- **Zero Cloud Leakage:** Runs 100% locally on consumer hardware via Ollama (`Q4_K_M`, ~4.7 GB VRAM/RAM) so proprietary source code and diffs never leave your machine.
- **AST-Level Signal Over Raw Diff Noise:** Instead of feeding fragmented `@@` hunks to an LLM, Tree-sitter extracts the outermost enclosing function or React component—including deletion anchors when authorization guards or checks are removed.
- **Agentic Verification:** Actuator-7B inspects external callers, types, and imports across the codebase using parallel, deduplication-cached tool calls before flagging a defect.
- **Deterministic Abstention & Structured Output:** Enforces Pydantic JSON schema decoding (`SliceReview`) and confidence filtering so clean diffs pass cleanly without hallucinated nitpicks.

## Architecture

```text
git diff ──▶ Tree-sitter AST Slicer ──▶ Actuator-7B Agent Loop ──▶ Constrained SliceReview JSON
                    │                            │
                    ▼                            ▼
         Outermost enclosing AST      Sandboxed RepoToolbox (cached)
         functions + diff patch       • search_symbol
                                      • read_file
                                      • get_file_imports
```

1. **Diff & Deletion-Anchor Extraction (`src/codewarden/git_diff.py`):** Parses unified diffs for both added lines and deletion anchors, ensuring security regressions caused by removing validation or ownership checks are captured.
2. **AST Function Slicing (`src/codewarden/ast_slicer.py`):** Uses Tree-sitter (`Python`, `TypeScript`, `TSX`, `C++`) to isolate the outermost enclosing functions/components overlapping modified lines, avoiding duplicate inner-callback noise.
3. **Sandboxed Repository Toolbox (`src/codewarden/tools.py`):** Exposes path-traversal-guarded, deduplication-cached tools (`search_symbol`, `read_file`, `get_file_imports`) with runtime/framework builtin filtering so the agent only queries project-specific symbols.
4. **Structured Agent Loop (`src/codewarden/agent.py`):** Executes multi-step parallel tool exploration with `actuator-7b:latest` and enforces Pydantic schema decoding (`SliceReview`) on the final synthesis turn.
5. **CLI & Telemetry (`src/codewarden/cli.py`):** Built with Typer and Rich for syntax-highlighted AST slice inspection, live tool-call tracing, severity filtering, and CI-ready JSON report exports.

## Quickstart

### Prerequisites

- **Python 3.12+** and [`uv`](https://docs.astral.sh/uv/)
- **[Ollama](https://ollama.com/)** with Actuator-7B available locally:

```bash
ollama pull hf.co/nihalmotukuri/actuator-7b-gguf:Q4_K_M
ollama cp hf.co/nihalmotukuri/actuator-7b-gguf:Q4_K_M actuator-7b:latest
```

### Installation

```bash
git clone [https://github.com/nihalmotukuri/CodeWarden.git](https://github.com/nihalmotukuri/CodeWarden.git)
cd codewarden
uv sync
```

## Usage

### 1. Preview Extracted AST Slices

Inspect the exact enclosing functions/components that CodeWarden extracts from a Git diff before running model inference:

```bash
uv run codewarden slice --repo /path/to/repo --base HEAD~1
```

### 2. Run an Agentic Security & Bug Review

Audit uncommitted working-tree changes, staged changes (`--staged`), or a commit/branch diff (`--base <ref>`):

```bash
# Audit against previous commit and export JSON report
uv run codewarden review --repo /path/to/repo --base HEAD~1 --json-out report.json

# Audit staged changes before committing
uv run codewarden review --repo /path/to/repo --staged
```

### CLI Options (`codewarden review`)

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--repo`, `-r` | `.` | Path to target Git repository |
| `--base`, `-b` | `None` | Compare against a base Git ref (e.g., `main`, `HEAD~1`) |
| `--staged`, `-s` | `False` | Audit staged changes only |
| `--model`, `-m` | `actuator-7b:latest` | Local Ollama model tag |
| `--host` | `http://localhost:11434` | Ollama server URL |
| `--min-severity` | `medium` | Minimum severity to display (`low`, `medium`, `high`, `critical`) |
| `--json-out` | `None` | Export structured `ReviewReport` JSON to path |

## Project Structure

```text
codewarden/
├── src/codewarden/
│   ├── __init__.py
│   ├── models.py       # Pydantic schemas (DiffHunk, FunctionSlice, ReviewFinding, SliceReview, ReviewReport)
│   ├── git_diff.py     # Unified diff parser with added-line & deletion-anchor tracking
│   ├── ast_slicer.py   # Tree-sitter multi-language outermost AST function slicer
│   ├── tools.py        # Sandboxed, cached RepoToolbox with builtin symbol filtering
│   ├── agent.py        # Actuator-7B parallel tool-calling loop & constrained JSON decoding
│   └── cli.py          # Typer + Rich CLI (`slice` and `review` commands)
├── tests/
│   └── test_codewarden.py
└── pyproject.toml
```

## Running Tests

Run the unit test suite (AST slicing, deletion-anchor extraction, path-traversal sandboxing, and caching) alongside the live Actuator-7B integration check:

```bash
# Fast unit tests only
uv run pytest -m "not integration" -v

# Full suite including live Actuator-7B vulnerability detection
uv run pytest -v
```

## License

MIT
