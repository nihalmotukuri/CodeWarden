import glob
from pathlib import Path
from huggingface_hub import HfApi, whoami

MODEL_REPO_SUFFIX = "codewarden-7b-gguf"
GGUF_SEARCH_DIR = "models"

CARD_LINES = [
    "---",
    "license: apache-2.0",
    "language:",
    "- en",
    "base_model: Qwen/Qwen2.5-Coder-7B-Instruct",
    "tags:",
    "- code",
    "- security",
    "- vulnerability-detection",
    "- gguf",
    "- ollama",
    "- qlora",
    "- unsloth",
    "library_name: gguf",
    "---",
    "",
    "# CodeWarden-7B (GGUF)",
    "",
    "100% Offline PR Security & Architecture Auditor fine-tuned from `Qwen/Qwen2.5-Coder-7B-Instruct` via 4-bit QLoRA (Unsloth).",
    "",
    "- GitHub: https://github.com/nihalmotukuri/CodeWarden",
    "- Quantization: `Q4_K_M` GGUF",
    "",
    "## Hold-Out Benchmark Results (RTX 5070 Ti 12GB)",
    "",
    "| Metric | Base (`Qwen2.5-Coder-7B`) | `CodeWarden-7B` |",
    "| :--- | :---: | :---: |",
    "| **Audit Schema Adherence** | 0.0% | **86.7%** |",
    "| **Verdict Classification** | 0.0% | **86.7%** |",
    "| **Avg Latency / Audit** | 4.51s | **2.69s (-40.4%)** |",
    "| **Throughput** | 84.3 tok/s | **68.7 tok/s** |",
    "",
    "## Quickstart with Ollama",
    "",
    "    huggingface-cli download {repo_id} --local-dir ./codewarden-7b",
    "    cd codewarden-7b",
    "    ollama create codewarden:7b -f Modelfile",
]


def main():
    api = HfApi()
    username = whoami()["name"]
    repo_id = f"{username}/{MODEL_REPO_SUFFIX}"

    gguf_files = glob.glob(f"{GGUF_SEARCH_DIR}/**/*.gguf", recursive=True)
    if not gguf_files:
        raise FileNotFoundError(f"No .gguf file found under {GGUF_SEARCH_DIR}/")
    gguf_path = Path(gguf_files[0])

    print(f"Creating/verifying Hugging Face repo: {repo_id}")
    api.create_repo(repo_id=repo_id, repo_type="model", exist_ok=True)

    hf_modelfile = Path("models/Modelfile.hf")
    hf_modelfile.write_text(
        f"FROM ./{gguf_path.name}\n"
        "PARAMETER temperature 0.1\n"
        "PARAMETER top_p 0.9\n"
        "PARAMETER num_ctx 4096\n",
        encoding="utf-8",
    )

    readme_path = Path("models/HF_README.md")
    readme_text = "\n".join(CARD_LINES).format(repo_id=repo_id) + "\n"
    readme_path.write_text(readme_text, encoding="utf-8")

    print(f"Uploading {gguf_path} ({gguf_path.stat().st_size / 1e9:.2f} GB)...")
    api.upload_file(path_or_fileobj=str(gguf_path), path_in_repo=gguf_path.name, repo_id=repo_id, repo_type="model")
    api.upload_file(path_or_fileobj=str(hf_modelfile), path_in_repo="Modelfile", repo_id=repo_id, repo_type="model")
    api.upload_file(path_or_fileobj=str(readme_path), path_in_repo="README.md", repo_id=repo_id, repo_type="model")

    print(f"Published! View your model at: https://huggingface.co/{repo_id}")


if __name__ == "__main__":
    main()
