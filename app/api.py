import re
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import requests

from app.router import run_codewarden, get_local_git_diff, OLLAMA_URL, MODEL_NAME

app = FastAPI(
    title="CodeWarden Local Security & Architecture Auditor API",
    description="100% offline PR security auditor powered by QLoRA fine-tuned Qwen2.5-Coder-7B via Ollama.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuditRequest(BaseModel):
    content: str = Field(..., description="Source code, unified Git diff, or engineering question")
    filename: Optional[str] = Field(None, description="Optional filename to assist language detection")
    force_audit: bool = Field(False, description="Force strict audit schema even for short snippets")
    block_on: list[str] = Field(default=["CRITICAL", "HIGH"], description="Severities that trigger blocked=True")


class DiffAuditRequest(BaseModel):
    repo_path: str = Field(".", description="Local filesystem path to Git repository")
    staged_only: bool = Field(True, description="Audit staged changes (--cached) vs working tree")
    block_on: list[str] = Field(default=["CRITICAL", "HIGH"])


class AuditResponse(BaseModel):
    mode: str
    language: str
    severity: str
    blocked: bool
    report: str
    tok_per_sec: float


def extract_severity(report: str, mode: str) -> str:
    if mode == "CHAT":
        return "INFO"
    if "Status: PASSED" in report:
        return "PASSED"
    match = re.search(r"Severity:\s*(CRITICAL|HIGH|MEDIUM|LOW)", report, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return "UNKNOWN"


@app.get("/health")
def health_check():
    try:
        base_url = OLLAMA_URL.replace("/api/chat", "/api/tags")
        resp = requests.get(base_url, timeout=5)
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]
        return {
            "status": "ok",
            "ollama_connected": True,
            "target_model": MODEL_NAME,
            "model_loaded": any(MODEL_NAME in m for m in models),
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Ollama unavailable: {e}")


@app.post("/audit", response_model=AuditResponse)
def audit_payload(req: AuditRequest):
    if not req.content.strip():
        raise HTTPException(status_code=400, detail="Content cannot be empty.")
    try:
        route, report, tps = run_codewarden(
            req.content, filename=req.filename, force_audit=req.force_audit
        )
        severity = extract_severity(report, route.mode)
        blocked = severity in {s.upper() for s in req.block_on}
        return AuditResponse(
            mode=route.mode,
            language=route.language,
            severity=severity,
            blocked=blocked,
            report=report,
            tok_per_sec=round(tps, 2),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/audit/diff", response_model=AuditResponse)
def audit_git_diff(req: DiffAuditRequest):
    try:
        diff_text = get_local_git_diff(repo_path=req.repo_path, staged_only=req.staged_only)
        if not diff_text:
            return AuditResponse(
                mode="AUDIT_DIFF",
                language="none",
                severity="PASSED",
                blocked=False,
                report="### ✅ Status: PASSED | No staged changes to audit.",
                tok_per_sec=0.0,
            )
        route, report, tps = run_codewarden(diff_text, filename="staged.diff", force_audit=True)
        severity = extract_severity(report, route.mode)
        blocked = severity in {s.upper() for s in req.block_on}
        return AuditResponse(
            mode=route.mode,
            language=route.language,
            severity=severity,
            blocked=blocked,
            report=report,
            tok_per_sec=round(tps, 2),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
