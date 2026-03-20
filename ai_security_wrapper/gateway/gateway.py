"""
Layer 1 — API Gateway
Enforces rate limiting, WAF rules, request size limits, and CORS.
Reads configuration from config/gateway.yaml.
"""

import os
from typing import Optional

import yaml
from fastapi import Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address

from ai_security_wrapper.audit.logger import audit


def _load_config() -> dict:
    config_path = os.path.join(
        os.path.dirname(__file__), "..", "config", "gateway.yaml"
    )
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


CONFIG = _load_config()
GW_CFG = CONFIG["gateway"]
WAF_CFG = GW_CFG.get("waf", {})
RATE_CFG = GW_CFG.get("rate_limit", {})
CORS_CFG = WAF_CFG.get("cors", {})
SERVER_CFG = GW_CFG.get("server", {})
SECURITY_HEADERS = WAF_CFG.get("security_headers", {})

# Rate limiter — uses client IP as the key
limiter = Limiter(key_func=get_remote_address)

BLOCKED_AGENTS = [ua.lower() for ua in WAF_CFG.get("blocked_user_agents", [])]


class GatewayMiddleware:
    """ASGI middleware that applies WAF checks on every incoming request."""

    def __init__(self, app):
        self.app = app
        request_limits = WAF_CFG.get("request_limits", {})
        self.max_body = request_limits.get("max_body_bytes", 1_048_576)
        self.max_url_length = request_limits.get("max_url_length", 2048)
        self.max_header_count = request_limits.get("max_header_count", 50)
        self.allowed_methods = set(WAF_CFG.get("allowed_methods", ["GET", "POST", "OPTIONS", "HEAD"]))

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        client_ip = get_remote_address(request)
        trace_id = request.headers.get("X-Trace-ID", "")

        # 1. Blocked user-agent check
        user_agent = request.headers.get("user-agent", "").lower()
        for blocked in BLOCKED_AGENTS:
            if blocked in user_agent:
                audit.log(
                    "WAF_BLOCK",
                    details={"reason": "Blocked user-agent", "rule_matched": blocked, "ip": client_ip, "path": scope.get("path")},
                    trace_id=trace_id,
                )
                response = Response(
                    content='{"detail":"Forbidden"}',
                    status_code=403,
                    media_type="application/json",
                )
                await response(scope, receive, send)
                return

        # 2. HTTP method check
        method = scope.get("method", "GET")
        if method not in self.allowed_methods:
            audit.log(
                "WAF_BLOCK",
                details={"reason": "Method not allowed", "rule_matched": method, "ip": client_ip, "path": scope.get("path")},
                trace_id=trace_id,
            )
            response = Response(
                content='{"detail":"Method not allowed"}',
                status_code=405,
                media_type="application/json",
            )
            await response(scope, receive, send)
            return

        # 3. Request body size check
        content_length = int(request.headers.get("content-length", 0))
        if content_length > self.max_body:
            audit.log(
                "REQUEST_TOO_LARGE",
                details={"ip": client_ip, "size_bytes": content_length, "limit_bytes": self.max_body},
                trace_id=trace_id,
            )
            response = Response(
                content='{"detail":"Request entity too large"}',
                status_code=413,
                media_type="application/json",
            )
            await response(scope, receive, send)
            return

        # 4. URL length check
        path = scope.get("path", "")
        query_string = scope.get("query_string", b"").decode("utf-8", errors="ignore")
        full_url = f"{path}?{query_string}" if query_string else path
        if len(full_url) > self.max_url_length:
            audit.log(
                "WAF_BLOCK",
                details={"reason": "URL too long", "ip": client_ip, "path": path[:200]},
                trace_id=trace_id,
            )
            response = Response(
                content='{"detail":"URI too long"}',
                status_code=414,
                media_type="application/json",
            )
            await response(scope, receive, send)
            return

        audit.log(
            "REQUEST_RECEIVED",
            details={"ip": client_ip, "path": path, "method": method, "user_agent": user_agent[:100], "content_length": content_length},
            trace_id=trace_id,
        )

        # Inject security headers into the response
        async def send_with_headers(message):
            if message["type"] == "http.response.start" and SECURITY_HEADERS:
                headers = list(message.get("headers", []))
                for name, value in SECURITY_HEADERS.items():
                    headers.append((name.lower().encode(), str(value).encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


def get_global_rpm() -> int:
    """Return the global requests-per-minute limit."""
    return RATE_CFG.get("global", {}).get("requests_per_minute", 60)


def apply_cors(app, origins: Optional[list] = None) -> None:
    """Attach CORSMiddleware to the FastAPI app."""
    allowed_origins = origins or CORS_CFG.get("allowed_origins", ["*"])
    allowed_methods = CORS_CFG.get("allowed_methods", ["*"])
    allowed_headers = CORS_CFG.get("allowed_headers", ["*"])
    allow_credentials = CORS_CFG.get("allow_credentials", True)
    max_age = CORS_CFG.get("max_age_seconds", 3600)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=allow_credentials,
        allow_methods=allowed_methods,
        allow_headers=allowed_headers,
        max_age=max_age,
    )
