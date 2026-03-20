"""
AI Security Wrapper — Main FastAPI Application
Wires all 6 security layers into a single request pipeline.
Reads server config from config/gateway.yaml, auth roles from config/auth.yaml.
"""

import os
from contextlib import asynccontextmanager
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from ai_security_wrapper.audit.logger import audit
from ai_security_wrapper.auth.middleware import generate_token, require_auth, ROLES_CFG
from ai_security_wrapper.gateway.gateway import GatewayMiddleware, apply_cors, limiter, get_global_rpm, SERVER_CFG
from ai_security_wrapper.output_filter.filter import filter_output
from ai_security_wrapper.sanitizer.sanitizer import sanitize
from ai_security_wrapper.agent import runner

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    audit.log("SERVER_START", details={"version": "1.0.0", "layers_active": ["gateway", "auth", "sanitizer", "agent", "output_filter", "audit"]})
    yield
    audit.log("SERVER_STOP", details={"event": "Server shutdown"})


# ── App initialization ──────────────────────────────────────────────────────
app = FastAPI(
    title="AI Security Wrapper",
    description="Security-hardened agentic AI pipeline",
    version="1.0.0",
    lifespan=lifespan,
)

# Attach rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Attach WAF middleware (Layer 1)
app.add_middleware(GatewayMiddleware)

# Attach CORS
apply_cors(app)


# ── Health check ────────────────────────────────────────────────────────────
@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "layers": ["gateway", "auth", "sanitizer", "agent", "output_filter", "audit"]}


# ── Token issuance (dev/test only — use a real IdP in production) ───────────
@app.post("/auth/token", tags=["auth"])
async def issue_token(user_id: str, role: str = "agent_user"):
    """
    Issue a JWT for development and testing.
    In production, replace this with your Identity Provider (OAuth2, SSO, etc.)
    """
    valid_roles = list(ROLES_CFG.keys())
    if role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Role must be one of: {valid_roles}")
    return generate_token(user_id=user_id, role=role)


# ── Main agent endpoint — all 6 layers run here ─────────────────────────────
@app.post("/agent/query", tags=["agent"])
@limiter.limit(f"{get_global_rpm()}/minute")
async def agent_query(
    request: Request,
    payload: dict = Depends(require_auth),
):
    """
    The main secured endpoint.

    Flow:
      Layer 1 (Gateway)        — rate limit + WAF already applied by middleware
      Layer 2 (Auth)           — JWT validated by require_auth dependency
      Layer 3 (Sanitizer)      — validates and sanitizes body here
      Layer 4 (Agent)          — calls runner.run()
      Layer 5 (Output filter)  — scans and redacts response
      Layer 6 (Audit)          — logged throughout
    """
    trace_id = request.headers.get("X-Trace-ID", str(uuid4()))
    user_id = payload.get("sub", "anonymous")
    role = payload.get("role", "read_only")

    # Check RBAC action permission
    from ai_security_wrapper.auth.middleware import check_permission
    if not check_permission(payload, "execute_tool"):
        audit.log("PERMISSION_DENIED", user_id=user_id, trace_id=trace_id,
                  details={"reason": "Role lacks execute_tool permission", "role": role, "action_attempted": "execute_tool"})
        raise HTTPException(status_code=403, detail="Insufficient permissions for agent query")

    # Parse body
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON")

    # Layer 3 — Input sanitization
    try:
        san_result = sanitize(body, user_id=user_id, trace_id=trace_id)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    clean_request = san_result.clean_request

    # Layer 4 — Agent (returns dict with response + context data)
    try:
        agent_result = runner.run(clean_request, user_id=user_id, trace_id=trace_id)
    except Exception as e:
        audit.log("AGENT_ERROR", user_id=user_id, trace_id=trace_id,
                  details={"error_type": type(e).__name__, "error_message_preview": str(e)[:200]}, level="ERROR")
        raise HTTPException(status_code=500, detail="Agent encountered an error")

    # Layer 5 — Output filter (on the LLM response text)
    filter_result = filter_output(agent_result["response"], user_id=user_id, trace_id=trace_id)

    return {
        "response": filter_result.filtered_text,
        "trace_id": trace_id,
        "meta": {
            "pii_redacted": filter_result.pii_found,
            "secrets_redacted": len(filter_result.secrets_found) > 0,
            "secret_types_found": filter_result.secrets_found,
            "policy_violations": filter_result.policy_violations,
            "truncated": filter_result.truncated,
            "registry_findings": filter_result.registry_findings,
            "context_guard_applied": agent_result.get("context_guard_applied", False),
            "context_guard_categories": agent_result.get("context_guard_categories", []),
            "raw_context": agent_result.get("raw_context", ""),
            "sanitized_context": agent_result.get("sanitized_context", ""),
            "warnings": san_result.warnings,
        },
    }


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "ai_security_wrapper.main:app",
        host=SERVER_CFG.get("host", "0.0.0.0"),
        port=SERVER_CFG.get("port", 8000),
        reload=SERVER_CFG.get("debug", False),
    )
