import json
import re
import random
import difflib
from datasets import load_dataset

random.seed(42)

AUDIT_SYSTEM_PROMPT = (
    "You are CodeWarden, a strict Staff Application Security & Architecture Auditor. "
    "Analyze the provided code or Git diff and respond strictly using the CodeWarden Audit Schema. "
    "Do not include conversational filler."
)

CHAT_SYSTEM_PROMPT = (
    "You are CodeWarden, a senior full-stack and security-minded software engineer. "
    "Provide clear, secure, production-ready coding guidance."
)

def strip_code_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z0-9_+-]*\n", "", text)
    text = re.sub(r"\n```$", "", text)
    return text.strip()

def classify_severity(vuln_text: str) -> str:
    v = vuln_text.lower()
    critical_kw = ["sql injection", "arbitrary code", "remote code", "command injection", "injection", "buffer overflow", "deserialization", "eval(", "exec("]
    high_kw = ["xss", "cross-site", "path traversal", "ssrf", "hardcoded", "authentication", "authorization", "csrf", "xxe", "race condition", "memory leak", "use after free"]
    if any(k in v for k in critical_kw):
        return "CRITICAL"
    if any(k in v for k in high_kw):
        return "HIGH"
    return "MEDIUM"

def is_clean_text(text: str) -> bool:
    if not text or len(text.strip()) < 40 or len(text) > 3500:
        return False
    bad_chars = sum(1 for c in text if ord(c) > 0x2E80)
    return bad_chars == 0

def make_buggy_pr_diff(safe_base: str, vulnerable_pr: str, lang: str) -> str:
    ext_map = {"python": "py", "javascript": "js", "typescript": "ts", "java": "java", "c++": "cpp", "go": "go", "php": "php", "c#": "cs"}
    ext = ext_map.get(lang.lower(), "txt")
    base_lines = strip_code_fences(safe_base).splitlines(keepends=True)
    vuln_lines = strip_code_fences(vulnerable_pr).splitlines(keepends=True)
    # Diff from clean base -> incoming vulnerable PR so '+' lines show the newly introduced bug
    diff = list(difflib.unified_diff(base_lines, vuln_lines, fromfile=f"a/src/handler.{ext}", tofile=f"b/src/handler.{ext}"))
    return "".join(diff)

def main():
    print("Loading CyberNative/Code_Vulnerability_Security_DPO...")
    ds = load_dataset("CyberNative/Code_Vulnerability_Security_DPO", split="train")
    
    valid_rows = []
    for row in ds:
        lang = str(row.get("lang", "")).strip().lower()
        vuln = str(row.get("vulnerability", "")).strip()
        question = str(row.get("question", "")).strip()
        chosen = str(row.get("chosen", "")).strip()
        rejected = str(row.get("rejected", "")).strip()

        if lang not in {"python", "javascript", "typescript", "java", "go", "c++", "php", "c#"}:
            continue
        if not (is_clean_text(chosen) and is_clean_text(rejected) and len(vuln) > 15):
            continue
        if strip_code_fences(chosen) == strip_code_fences(rejected):
            continue

        valid_rows.append({
            "lang": lang,
            "vuln": vuln,
            "question": question,
            "chosen": chosen,
            "rejected": rejected,
        })

    print(f"Filtered {len(valid_rows)} clean, high-signal vulnerability pairs.")
    random.shuffle(valid_rows)

    pool = valid_rows[:2700]
    vuln_pool = pool[:1940]
    clean_pool = pool[1940:2380]
    chat_pool = pool[2380:2700]

    formatted = []

    for idx, item in enumerate(vuln_pool):
        sev = classify_severity(item["vuln"])
        use_diff = (idx % 2 == 1)
        diff_text = make_buggy_pr_diff(item["chosen"], item["rejected"], item["lang"]) if use_diff else ""

        if use_diff and len(diff_text) > 40:
            user_msg = f"AUDIT_DIFF ({item['lang']}):\n```diff\n{diff_text.strip()}\n```"
            target_label = "incoming PR diff"
        else:
            clean_rej = strip_code_fences(item["rejected"])
            user_msg = f"AUDIT_CODE ({item['lang']}):\n```{item['lang']}\n{clean_rej}\n```"
            target_label = "submitted code"

        clean_chosen = strip_code_fences(item["chosen"])
        assistant_msg = (
            f"### 🚨 Severity: {sev} | Security & Architecture Audit\n\n"
            f"**Root Cause ({item['lang'].upper()}):** {item['vuln']}\n\n"
            f"**Exploit / Failure Scenario:** Untrusted input or unsafe state handling in the {target_label} "
            f"allows an attacker or malformed payload to trigger the vulnerability above.\n\n"
            f"**Drop-in Patched Code:**\n```{item['lang']}\n{clean_chosen}\n```"
        )

        formatted.append({
            "category": "vuln_audit",
            "messages": [
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
                {"role": "assistant", "content": assistant_msg},
            ]
        })

    for item in clean_pool:
        clean_chosen = strip_code_fences(item["chosen"])
        user_msg = f"AUDIT_CODE ({item['lang']}):\n```{item['lang']}\n{clean_chosen}\n```"
        assistant_msg = (
            f"### ✅ Status: PASSED | Security & Architecture Audit\n\n"
            f"**Assessment ({item['lang'].upper()}):** No critical or high-severity vulnerabilities detected. "
            f"The implementation properly mitigates risks related to: {item['vuln'].lower()}\n\n"
            f"**Recommendation:** Safe to merge. Maintain existing input validation and boundary checks."
        )
        formatted.append({
            "category": "clean_pass",
            "messages": [
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
                {"role": "assistant", "content": assistant_msg},
            ]
        })

    for item in chat_pool:
        formatted.append({
            "category": "general_chat",
            "messages": [
                {"role": "system", "content": CHAT_SYSTEM_PROMPT},
                {"role": "user", "content": item["question"]},
                {"role": "assistant", "content": item["chosen"]},
            ]
        })

    random.shuffle(formatted)
    train_data = formatted[:2500]
    eval_data = formatted[2500:2700]

    with open("data/train.jsonl", "w", encoding="utf-8") as f:
        for row in train_data:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    with open("data/eval.jsonl", "w", encoding="utf-8") as f:
        for row in eval_data:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    with open("data/sample_train.jsonl", "w", encoding="utf-8") as f:
        for row in train_data[:6]:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"Rebuilt {len(train_data)} train rows and {len(eval_data)} eval rows cleanly!")

if __name__ == "__main__":
    main()
