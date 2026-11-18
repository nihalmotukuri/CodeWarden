import torch
from datasets import load_dataset
from unsloth import FastLanguageModel
from unsloth.chat_templates import get_chat_template, train_on_responses_only
from trl import SFTTrainer, SFTConfig

MODEL_NAME = "unsloth/Qwen2.5-Coder-7B-Instruct-bnb-4bit"
MAX_SEQ_LENGTH = 2048
OUTPUT_DIR = "models/codewarden-7b-lora"

def main():
    print(f"Loading base model: {MODEL_NAME}...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=MODEL_NAME,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=None,          # Auto-detects bfloat16 on RTX 5070 Ti
        load_in_4bit=True,
    )

    # Attach LoRA adapters to attention + MLP layers
    model = FastLanguageModel.get_peft_model(
        model,
        r=16,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_alpha=16,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )

    tokenizer = get_chat_template(tokenizer, chat_template="qwen-2.5")

    def format_chat(examples):
        texts = [
            tokenizer.apply_chat_template(
                msgs, tokenize=False, add_generation_prompt=False
            )
            for msgs in examples["messages"]
        ]
        return {"text": texts}

    print("Loading and formatting train/eval datasets...")
    train_ds = load_dataset("json", data_files="data/train.jsonl", split="train")
    eval_ds = load_dataset("json", data_files="data/eval.jsonl", split="train")

    train_ds = train_ds.map(format_chat, batched=True)
    eval_ds = eval_ds.map(format_chat, batched=True)

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        dataset_text_field="text",
        max_seq_length=MAX_SEQ_LENGTH,
        dataset_num_proc=4,
        packing=False,
        args=SFTConfig(
            per_device_train_batch_size=2,
            gradient_accumulation_steps=8,
            warmup_steps=15,
            num_train_epochs=2,
            learning_rate=2e-4,
            bf16=True,
            logging_steps=10,
            eval_strategy="steps",
            eval_steps=50,
            save_strategy="steps",
            save_steps=100,
            save_total_limit=2,
            optim="adamw_8bit",
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            seed=42,
            output_dir="checkpoints",
            report_to="none",
        ),
    )

    # Compute loss ONLY on assistant responses (ignores user prompt tokens)
    trainer = train_on_responses_only(
        trainer,
        instruction_part="<|im_start|>user\n",
        response_part="<|im_start|>assistant\n",
    )

    print("Starting QLoRA training on RTX 5070 Ti...")
    stats = trainer.train()
    print(f"Training complete! Final train loss: {stats.training_loss:.4f}")

    print(f"Saving LoRA adapters to {OUTPUT_DIR}...")
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print("Done! Ready for Phase 3 (GGUF Export & Ollama).")

if __name__ == "__main__":
    main()
