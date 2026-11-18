from datasets import load_dataset

print("Fetching sample rows from CyberNative/Code_Vulnerability_Security_DPO...")
ds = load_dataset("CyberNative/Code_Vulnerability_Security_DPO", split="train", streaming=True)

for i, row in enumerate(ds.take(3)):
    print(f"\n--- ROW {i+1} ---")
    for k, v in row.items():
        preview = str(v)[:200].replace("\n", " ")
        print(f"{k}: {preview}...")
