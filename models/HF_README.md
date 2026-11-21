---
license: apache-2.0
language:
- en
base_model: Qwen/Qwen2.5-Coder-7B-Instruct
tags:
- code
- security
- vulnerability-detection
- gguf
- ollama
- qlora
- unsloth
library_name: gguf
---

# CodeWarden-7B (GGUF)

100% Offline PR Security & Architecture Auditor fine-tuned from `Qwen/Qwen2.5-Coder-7B-Instruct` via 4-bit QLoRA (Unsloth).

- GitHub: https://github.com/nihalmotukuri/CodeWarden
- Quantization: `Q4_K_M` GGUF

## Hold-Out Benchmark Results (RTX 5070 Ti 12GB)

| Metric | Base (`Qwen2.5-Coder-7B`) | `CodeWarden-7B` |
| :--- | :---: | :---: |
| **Audit Schema Adherence** | 0.0% | **86.7%** |
| **Verdict Classification** | 0.0% | **86.7%** |
| **Avg Latency / Audit** | 4.51s | **2.69s (-40.4%)** |
| **Throughput** | 84.3 tok/s | **68.7 tok/s** |

## Quickstart with Ollama

    huggingface-cli download nihalmotukuri/codewarden-7b-gguf --local-dir ./codewarden-7b
    cd codewarden-7b
    ollama create codewarden:7b -f Modelfile
