# 🛡️ CodeWarden: Local Offline PR Security & Architecture Auditor

A 100% offline, privacy-first AI code reviewer and security auditor powered by a QLoRA fine-tuned **Qwen2.5-Coder-7B-Instruct** model running locally via **Ollama**. Scans Git diffs and source files to catch security flaws and block vulnerable commits before you push—without your code ever leaving your machine.

- **🤗 Hugging Face Model Weights (GGUF):** [nihalmotukuri/codewarden-7b-gguf](https://huggingface.co/nihalmotukuri/codewarden-7b-gguf)

## 📊 Hold-Out Benchmark Results (NVIDIA RTX 5070 Ti 12GB)

Evaluated locally across 30 unseen vulnerability & clean code audit tasks:

| Metric | Base (`Qwen2.5-Coder-7B`) | `CodeWarden-7B` (Fine-Tuned) |
| :--- | :---: | :---: |
| **Audit Schema Adherence** | 0.0% | **86.7%** |
| **Verdict Classification** | 0.0% | **86.7%** |
| **Avg Latency / Audit** | 4.51s | **2.69s (-40.4%)** |
| **Throughput** | 84.3 tok/s | **68.7 tok/s** |

## 🏗️ Architecture
1. **Dataset Engineering (`scripts/build_dataset.py`):** Curated 2,500 multi-task pairs across 8 languages combining unified Git diffs (`difflib`), vulnerable code audits, clean code false-positive checks (`PASSED`), and general secure coding Q&A.
2. **QLoRA Fine-Tuning (`scripts/train.py`):** Trained `Qwen2.5-Coder-7B-Instruct` via Unsloth (4-bit QLoRA, `r=16`, `train_on_responses_only`) in `bfloat16`.
3. **Local GGUF Inference (`scripts/export_gguf.py`):** Merged LoRA weights, quantized to `Q4_K_M` GGUF, published to Hugging Face, and served locally via Ollama (`localhost:11434`).
4. **Developer Interfaces (`app/` & `scripts/install_hook.py`):**
   - **Dynamic Intent Router (`app/router.py`):** Automatically switches between strict security audit reports (`AUDIT_DIFF` / `AUDIT_CODE`) and conversational engineering Q&A (`CHAT`).
   - **CLI & Pre-Commit Security Gate (`app/cli.py`, `scripts/install_hook.py`):** Audits staged diffs (`git diff --cached`) and automatically blocks commits on `CRITICAL`/`HIGH` findings.
   - **FastAPI Microservice (`app/api.py`) & Streamlit UI (`app/ui.py`):** REST endpoints (`/audit`, `/audit/diff`, `/health`) and interactive local web dashboard.

## 🚀 Quickstart

```bash
# 1. Pull quantized weights from Hugging Face & register in Ollama
huggingface-cli download nihalmotukuri/codewarden-7b-gguf --local-dir ./codewarden-7b
ollama create codewarden:7b -f ./codewarden-7b/Modelfile

# 2. Audit uncommitted changes in any local Git repo
python -m app.cli diff --repo /path/to/repo

# 3. Install automated Git pre-commit security hook
python scripts/install_hook.py /path/to/repo

# 4. Launch Streamlit UI or FastAPI server
streamlit run app/ui.py --server.headless true
uvicorn app.api:app --host 0.0.0.0 --port 8000
