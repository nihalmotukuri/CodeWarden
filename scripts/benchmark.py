import json
import time
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
EVAL_FILE = "data/eval.jsonl"
NUM_SAMPLES = 30

AUDIT_SYSTEM_PROMPT = (
    "You are CodeWarden, a strict Staff Application Security & Architecture Auditor. "
    "Analyze the provided code or Git diff and respond strictly using the CodeWarden Audit Schema. "
    "Do not include conversational filler."
)


def check_schema_adherence(output: str, category: str) -> tuple[bool, bool]:
    text = output.strip()
    if category == "vuln_audit":
        has_header = text.startswith("### 🚨 Severity:")
        has_sections = (
            ("**Root Cause" in text)
            and ("**Exploit / Failure Scenario:**" in text)
            and ("**Drop-in Patched Code:**" in text)
        )
        schema_ok = has_header and has_sections
        verdict_ok = any(s in text for s in ["Severity: CRITICAL", "Severity: HIGH", "Severity: MEDIUM"])
        return schema_ok, verdict_ok
    else:
        has_header = text.startswith("### ✅ Status: PASSED")
        has_sections = ("**Assessment" in text) and ("**Recommendation:**" in text)
        schema_ok = has_header and has_sections
        verdict_ok = "Status: PASSED" in text
        return schema_ok, verdict_ok


def evaluate_model(model_name: str, samples: list[dict]) -> dict:
    print(f"\nEvaluating {model_name} on {len(samples)} unseen audit cases...")
    schema_hits = 0
    verdict_hits = 0
    latencies = []
    tps_list = []

    for idx, item in enumerate(samples, 1):
        user_prompt = item["messages"][1]["content"]
        category = item["category"]

        t0 = time.perf_counter()
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": model_name,
                "messages": [
                    {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                "options": {"temperature": 0.1},
                "stream": False,
            },
            timeout=120,
        )
        resp.raise_for_status()
        elapsed = time.perf_counter() - t0
        data = resp.json()

        reply = data["message"]["content"]
        eval_count = data.get("eval_count", 0)
        eval_dur = data.get("eval_duration", 1)
        tps = eval_count / (eval_dur / 1e9) if eval_dur > 0 else 0.0

        schema_ok, verdict_ok = check_schema_adherence(reply, category)
        schema_hits += int(schema_ok)
        verdict_hits += int(verdict_ok)
        latencies.append(elapsed)
        tps_list.append(tps)

        if idx % 10 == 0:
            print(f"  [{idx}/{len(samples)}] Schema: {schema_hits}/{idx} | Verdict: {verdict_hits}/{idx} | {tps:.1f} tok/s")

    n = len(samples)
    return {
        "schema_adherence": (schema_hits / n) * 100,
        "verdict_accuracy": (verdict_hits / n) * 100,
        "avg_latency_s": sum(latencies) / n,
        "avg_tps": sum(tps_list) / n,
    }


def main():
    audit_samples = []
    with open(EVAL_FILE, "r", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            if row["category"] in {"vuln_audit", "clean_pass"}:
                audit_samples.append(row)
            if len(audit_samples) >= NUM_SAMPLES:
                break

    base_res = evaluate_model("qwen2.5-coder:7b", audit_samples)
    ft_res = evaluate_model("codewarden:7b", audit_samples)

    print("\n" + "=" * 78)
    print(f"{'Metric':<28} | {'Base (Qwen2.5-Coder-7B)':<22} | {'CodeWarden-7B (Fine-Tuned)':<22}")
    print("-" * 78)
    print(f"{'Schema Adherence':<28} | {base_res['schema_adherence']:>20.1f}% | {ft_res['schema_adherence']:>20.1f}%")
    print(f"{'Verdict Classification':<28} | {base_res['verdict_accuracy']:>20.1f}% | {ft_res['verdict_accuracy']:>20.1f}%")
    print(f"{'Avg Latency / Audit':<28} | {base_res['avg_latency_s']:>19.2f}s | {ft_res['avg_latency_s']:>19.2f}s")
    print(f"{'Throughput':<28} | {base_res['avg_tps']:>16.1f} tok/s | {ft_res['avg_tps']:>16.1f} tok/s")
    print("=" * 78)


if __name__ == "__main__":
    main()
