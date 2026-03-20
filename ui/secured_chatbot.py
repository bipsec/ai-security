"""UI 2 — Secured RAG Chatbot (6-Layer AI Security Pipeline)
Calls the FastAPI backend which enforces all security layers.
Shows pre-LLM context guard, post-LLM output filter, and response quality.
Run: streamlit run ui/secured_chatbot.py --server.port 8502
Requires FastAPI backend running on port 8000.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import requests
import streamlit as st
from ui.common.styles import inject_secured_styles
from ui.common.attack_prompts import ATTACK_PROMPTS

st.set_page_config(
    page_title="FinNova RAG - SECURED (6-Layer Pipeline)",
    page_icon="\U0001F512",
    layout="wide",
)

inject_secured_styles()

API_BASE = "http://localhost:8000"

# Custom session to avoid WAF blocking the default python-requests user agent
_http = requests.Session()
_http.headers["User-Agent"] = "FinNova-SecuredUI/1.0"


# ── Token management ─────────────────────────────────────────────────────────
def get_token():
    resp = _http.post(
        f"{API_BASE}/auth/token",
        params={"user_id": "demo_user", "role": "agent_user"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def ensure_token():
    if "jwt_token" not in st.session_state or st.session_state.jwt_token is None:
        st.session_state.jwt_token = get_token()
    return st.session_state.jwt_token


def query_secured_api(message: str):
    """Call the secured /agent/query endpoint. Returns (status_code, data_dict)."""
    token = ensure_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    resp = _http.post(
        f"{API_BASE}/agent/query",
        json={"message": message},
        headers=headers,
        timeout=60,
    )

    # Token expired — refresh once and retry
    if resp.status_code == 401:
        st.session_state.jwt_token = get_token()
        headers["Authorization"] = f"Bearer {st.session_state.jwt_token}"
        resp = _http.post(
            f"{API_BASE}/agent/query",
            json={"message": message},
            headers=headers,
            timeout=60,
        )

    try:
        data = resp.json()
    except Exception:
        data = {"detail": resp.text}

    return resp.status_code, data


# ── Session state init ───────────────────────────────────────────────────────
if "messages" not in st.session_state:
    st.session_state.messages = []

if "pending_input" not in st.session_state:
    st.session_state.pending_input = None


# ── Check backend connectivity ───────────────────────────────────────────────
def check_backend():
    try:
        r = _http.get(f"{API_BASE}/health", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


backend_ok = check_backend()


# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        '<div class="sidebar-success">'
        "\U0001F6E1 <b>6-LAYER SECURITY ACTIVE</b><br>"
        "All queries pass through the full AI security pipeline."
        "</div>",
        unsafe_allow_html=True,
    )

    st.markdown("**Security Layers:**")
    st.markdown(
        "1. \U0001F6E1 API Gateway (WAF + Rate Limiting)\n"
        "2. \U0001F511 Authentication (JWT + RBAC)\n"
        "3. \U0001F9F9 Input Sanitizer (Injection Detection)\n"
        "4. \U0001F916 Agent (RAG + **Context Guard**)\n"
        "5. \U0001F50D Output Filter (PII + Registry Redaction)\n"
        "6. \U0001F4DD Audit Logger"
    )

    st.markdown("---")

    if st.button("\U0001F5D1 Clear Chat", use_container_width=True):
        st.session_state.messages = []
        st.session_state.pending_input = None
        st.rerun()

    st.markdown("---")
    st.markdown("### \U0001F9EA Test Prompts")

    for category, prompts in ATTACK_PROMPTS.items():
        with st.expander(category):
            for prompt in prompts:
                if st.button(prompt, key=f"sec_{hash(prompt)}"):
                    st.session_state.pending_input = prompt
                    st.rerun()


# ── Header ───────────────────────────────────────────────────────────────────
st.markdown(
    '<div class="banner-secured">'
    "\U0001F512 SECURED RAG Chatbot &mdash; 6-Layer AI Security Pipeline"
    "</div>",
    unsafe_allow_html=True,
)
st.caption("All queries pass through: Gateway \u2192 Auth \u2192 Sanitizer \u2192 Context Guard \u2192 Agent \u2192 Output Filter \u2192 Audit Logger")

if not backend_ok:
    st.error(
        "\u274C **FastAPI backend is not running!**\n\n"
        "Start it with:\n```\npython -m ai_security_wrapper.main\n```\n"
        "Or use `python ui/start_demo.py` to start everything."
    )
    st.stop()


# ── Response quality detection ───────────────────────────────────────────────
_REDIRECT_PHRASES = [
    "i don't have enough information",
    "i cannot access personal",
    "i cannot provide",
    "please contact support",
    "please contact our support",
    "please check your account",
    "please refer to the official",
    "i'm sorry, i cannot",
    "i am sorry, i cannot",
    "i'm unable to",
    "for your security",
    "contact support@finnova.com",
]


def _detect_response_quality(response_text: str) -> str:
    """Detect if response is grounded or redirected to support."""
    lower = response_text.lower()
    for phrase in _REDIRECT_PHRASES:
        if phrase in lower:
            return "redirected"
    if len(response_text.strip()) < 50:
        return "minimal"
    return "grounded"


# ── Security report renderer ────────────────────────────────────────────────
def _render_security_report(meta: dict, status_code: int, response_text: str = ""):
    """Render the security pipeline visualization after an assistant message."""
    if not meta:
        return

    # Blocked requests
    if "blocked_at" in meta:
        with st.expander("\U0001F6E1 Security Report", expanded=True):
            st.markdown(
                f'<span class="badge-blocked">\u26D4 BLOCKED at {meta["blocked_at"]}</span>',
                unsafe_allow_html=True,
            )
            if "detail" in meta:
                st.code(meta["detail"], language=None)
        return

    # ── PRE-LLM CHECK: Context Guard ────────────────────────────
    raw_ctx = meta.get("raw_context", "")
    san_ctx = meta.get("sanitized_context", "")
    guard_applied = meta.get("context_guard_applied", False)
    guard_cats = meta.get("context_guard_categories", [])

    if guard_applied and raw_ctx:
        with st.expander("\U0001F6E1 Pre-LLM Check — Context Guard", expanded=False):
            if guard_cats:
                st.markdown("**Categories redacted before LLM saw the context:**")
                for cat in guard_cats:
                    st.markdown(
                        f'<span class="badge-guard">\U0001F6E1 {cat}</span> ',
                        unsafe_allow_html=True,
                    )
                st.markdown("")

            col_raw, col_san = st.columns(2)
            with col_raw:
                st.markdown("**Raw Retrieved Context** (what retriever fetched)")
                st.markdown(
                    f'<div class="context-diff-raw">{_escape(raw_ctx[:3000])}</div>',
                    unsafe_allow_html=True,
                )
            with col_san:
                st.markdown("**Sanitized Context** (what LLM actually saw)")
                st.markdown(
                    f'<div class="context-diff-sanitized">{_escape(san_ctx[:3000])}</div>',
                    unsafe_allow_html=True,
                )

    # ── POST-LLM CHECK: Output Filter ──────────────────────────
    with st.expander("\U0001F50D Post-LLM Check — Output Filter", expanded=False):
        cols = st.columns(4)

        pii = meta.get("pii_redacted", False)
        with cols[0]:
            if pii:
                st.markdown('<span class="badge-redacted">\U0001F510 PII Redacted</span>', unsafe_allow_html=True)
            else:
                st.markdown('<span class="badge-passed">\u2705 No PII</span>', unsafe_allow_html=True)

        secrets = meta.get("secrets_redacted", False)
        with cols[1]:
            if secrets:
                st.markdown('<span class="badge-redacted">\U0001F510 Secrets Redacted</span>', unsafe_allow_html=True)
            else:
                st.markdown('<span class="badge-passed">\u2705 No Secrets</span>', unsafe_allow_html=True)

        violations = meta.get("policy_violations", [])
        with cols[2]:
            if violations:
                st.markdown('<span class="badge-blocked">\u26D4 Policy Violation</span>', unsafe_allow_html=True)
            else:
                st.markdown('<span class="badge-passed">\u2705 Policy OK</span>', unsafe_allow_html=True)

        truncated = meta.get("truncated", False)
        with cols[3]:
            if truncated:
                st.markdown('<span class="badge-redacted">\u2702 Truncated</span>', unsafe_allow_html=True)
            else:
                st.markdown('<span class="badge-passed">\u2705 Full Response</span>', unsafe_allow_html=True)

        # Registry findings
        registry = meta.get("registry_findings", [])
        if registry:
            st.markdown("---")
            st.markdown("**\U0001F50D Sensitive Value Registry:**")
            for cat in registry:
                st.markdown(f'<span class="badge-redacted">\U0001F6AB {cat}</span>', unsafe_allow_html=True)

    # ── RESPONSE QUALITY ────────────────────────────────────────
    quality = _detect_response_quality(response_text)
    if quality == "redirected":
        st.markdown(
            '<span class="badge-quality-redirected">\U0001F6E1 Response safely redirected to support</span>',
            unsafe_allow_html=True,
        )
    elif quality == "minimal":
        st.markdown(
            '<span class="badge-quality-redirected">\u2139 Minimal response (context was heavily redacted)</span>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<span class="badge-quality-grounded">\u2705 Grounded response from documentation</span>',
            unsafe_allow_html=True,
        )

    if meta.get("trace_id"):
        st.caption(f"Trace ID: `{meta['trace_id']}`")


def _escape(text: str) -> str:
    """Escape HTML for safe rendering in markdown."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\n", "<br>")
    )


# ── Chat history ─────────────────────────────────────────────────────────────
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])
        if msg["role"] == "assistant" and "meta" in msg:
            _render_security_report(msg["meta"], msg.get("status_code", 200), msg["content"])


# ── Handle pending input from sidebar buttons ───────────────────────────────
user_input = st.chat_input("Ask anything...")

if st.session_state.pending_input:
    user_input = st.session_state.pending_input
    st.session_state.pending_input = None

# ── Process input ────────────────────────────────────────────────────────────
if user_input:
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    with st.chat_message("assistant"):
        with st.spinner("Processing through security pipeline..."):
            try:
                status_code, data = query_secured_api(user_input)
            except (requests.ConnectionError, requests.RequestException):
                status_code = 0
                data = {"detail": "Cannot connect to FastAPI backend"}

        if status_code == 200:
            response = data.get("response", "")
            meta = data.get("meta", {})
            meta["trace_id"] = data.get("trace_id", "")
        elif status_code == 422:
            response = f"\u26D4 **BLOCKED by Input Sanitizer (Layer 3)**\n\n{data.get('detail', 'Prompt injection detected')}"
            meta = {"blocked_at": "Layer 3 — Input Sanitizer", "detail": data.get("detail", "")}
        elif status_code == 403:
            response = f"\u26D4 **BLOCKED by Auth Layer (Layer 2)**\n\n{data.get('detail', 'Permission denied')}"
            meta = {"blocked_at": "Layer 2 — Authentication"}
        elif status_code == 500:
            response = f"\u26A0 **Agent Error (Layer 4)**\n\n{data.get('detail', 'Internal error')}"
            meta = {"blocked_at": "Layer 4 — Agent Error"}
        else:
            response = f"\u26A0 **Error ({status_code})**\n\n{data.get('detail', 'Unknown error')}"
            meta = {}

        st.markdown(response)
        _render_security_report(meta, status_code, response)

    st.session_state.messages.append({
        "role": "assistant",
        "content": response,
        "meta": meta,
        "status_code": status_code,
    })
