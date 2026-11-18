# 🛡️ CodeWarden: Local Offline PR Security & Architecture Auditor

A 100% offline, privacy-first AI code reviewer and security auditor powered by a QLoRA fine-tuned **Qwen2.5-Coder-7B-Instruct** model running locally via **Ollama**. Scans Git diffs and source files to catch security flaws and anti-patterns before you push—without your code ever leaving your machine.

## 📊 Benchmark Results (Hold-Out Eval Set)

Evaluated locally on an **NVIDIA RTX 5070 Ti (12GB VRAM)** across 30 unseen vulnerability & clean code audit tasks:

| Metric | Base (`Qwen2.5-Coder-7B`) | `CodeWarden-7B` (Fine-Tuned) |
| :--- | :---: | :---: |
| **Audit Schema Adherence** | 0.0% | **86.7%** |
| **Verdict Classification** | 0.0% | **86.7%** |
| **Avg Latency / Audit** | 4.51s | **2.69s (-40.4%)** |
| **Throughput** | 84.3 tok/s | **68.7 tok/s** |

## 🏗️ Architecture
1. **Dataset Engineering (`scripts/build_dataset.py`):** Curated 2,500 training pairs across 8 languages combining unified Git diffs (`difflib`), vulnerable code audits, clean code false-positive checks (`PASSED`), and general secure coding Q&A.
2. **QLoRA Fine-Tuning (`scripts/train.py`):** Trained `Qwen2.5-Coder-7B-Instruct` via Unsloth (4-bit QLoRA, `r=16`, `train_on_responses_only`) in `bfloat16`.
3. **Local GGUF Inference (`scripts/export_gguf.py`):** Merged LoRA weights, quantized to `Q4_K_M` GGUF, and served locally via Ollama (`localhost:11434`).
4. **Dynamic Intent Router (`app/router.py`):** Automatically detects unified diffs, source code files, or natural-language queries to toggle between strict security audit reports and conversational pair-programming.

## 🚀 Quickstart

```bash
# Audit uncommitted changes in any local Git repo
python -m app.cli diff --repo /path/to/repo

# Audit a specific source file
python -m app.cli file app/router.py

# Launch the local Streamlit UI
streamlit run app/ui.py --server.headless true
