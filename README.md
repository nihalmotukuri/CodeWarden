# 🛡️ Local PR Security & Architecture Auditor

An offline, privacy-first AI code reviewer and security auditor powered by a QLoRA fine-tuned **Qwen2.5-Coder-7B-Instruct** model running locally via **Ollama**.

## Architecture
1. **Fine-Tuned Brain:** `Qwen2.5-Coder-7B-Instruct` trained via Unsloth (4-bit QLoRA) on curated vulnerability patches (CWE) and architectural anti-patterns.
2. **Local Inference:** Quantized to `Q4_K_M` GGUF and served locally over Ollama (`localhost:11434`).
3. **Dynamic Intent Router:** Automatically routes `git diff` / source code inputs into strict structured security reports while keeping general queries conversational.

## Project Structure
- `data/` — Dataset curation & ChatML formatting pipelines
- `scripts/` — Unsloth SFT training, GGUF export, and automated eval benchmarks
- `models/` — Local LoRA adapters & Modelfile configs (weights gitignored)
- `app/` — Intent router, CLI scanner, and local web UI
