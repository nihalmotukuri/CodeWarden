from unsloth import FastLanguageModel

LORA_DIR = "models/codewarden-7b-lora"
GGUF_DIR = "models/codewarden-7b-gguf"

def main():
    print(f"Loading fine-tuned LoRA model from {LORA_DIR}...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=LORA_DIR,
        max_seq_length=2048,
        dtype=None,
        load_in_4bit=True,
    )

    print(f"Merging LoRA weights and quantizing to Q4_K_M GGUF in {GGUF_DIR}...")
    model.save_pretrained_gguf(
        GGUF_DIR,
        tokenizer,
        quantization_method="q4_k_m",
    )
    print("GGUF export complete!")

if __name__ == "__main__":
    main()
