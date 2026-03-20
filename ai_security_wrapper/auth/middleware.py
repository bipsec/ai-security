"""
Layer 2 — Authentication & RBAC Middleware
Validates JWT tokens and resolves user roles and permitted actions.
Reads configuration from config/auth.yaml.
"""

import os
from datetime import datetime, timedelta, timezone

import jwt
import yaml
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ai_security_wrapper.audit.logger import audit

load_dotenv()


def _load_config() -> dict:
    config_path = os.path.join(
        os.path.dirname(__file__), "..", "config", "auth.yaml"
    )
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


CONFIG = _load_config()
AUTH_CFG = CONFIG["auth"]
ACCESS_TOKEN_CFG = AUTH_CFG.get("access_token", {})
ROLES_CFG = AUTH_CFG.get("roles", {})

JWT_SECRET = os.getenv("JWT_SECRET", "INSECURE_DEFAULT_CHANGE_ME")
JWT_ALGORITHM = ACCESS_TOKEN_CFG.get("algorithm", "HS256")
TOKEN_EXPIRY_MINUTES = ACCESS_TOKEN_CFG.get("expiry_minutes", 60)

security_scheme = HTTPBearer()


class AuthError(Exception):
    pass


def generate_token(user_id: str, role: str) -> dict:
    """
    Generate a signed JWT for a user.
    Returns {"access_token": ..., "token_type": "bearer", "expires_in": ...}
    """
    if role not in ROLES_CFG:
        raise AuthError(f"Unknown role: {role}")

    # Use per-role token expiry override if set
    role_cfg = ROLES_CFG[role]
    expiry = role_cfg.get("token_expiry_override_minutes") or TOKEN_EXPIRY_MINUTES

    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=expiry),
        "iss": ACCESS_TOKEN_CFG.get("issuer", "ai-security-wrapper"),
        "aud": ACCESS_TOKEN_CFG.get("audience", "ai-security-wrapper-api"),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expiry * 60,
    }


def decode_token(token: str) -> dict:
    """Decode and validate a JWT. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer=ACCESS_TOKEN_CFG.get("issuer", "ai-security-wrapper"),
            audience=ACCESS_TOKEN_CFG.get("audience", "ai-security-wrapper-api"),
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def check_permission(payload: dict, action: str) -> bool:
    """Return True if the token's role permits the action."""
    role = payload.get("role", "read_only")
    role_cfg = ROLES_CFG.get(role, {})
    allowed_actions = role_cfg.get("allowed_actions", [])
    return action in allowed_actions


async def require_auth(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> dict:
    """
    FastAPI dependency — validates JWT and returns the decoded payload.
    Usage: payload = Depends(require_auth)
    """
    payload = decode_token(credentials.credentials)
    audit.log(
        "AUTH_SUCCESS",
        user_id=payload.get("sub"),
        details={"role": payload.get("role")},
    )
    return payload


async def require_action(action: str):
    """
    FastAPI dependency factory — validates JWT AND checks a specific action.
    Usage: payload = Depends(require_action("execute_tool"))
    """

    async def _dependency(
        credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    ) -> dict:
        payload = decode_token(credentials.credentials)
        if not check_permission(payload, action):
            audit.log(
                "PERMISSION_DENIED",
                user_id=payload.get("sub"),
                details={"reason": "Insufficient permissions", "action_attempted": action, "role": payload.get("role")},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{payload.get('role')}' is not permitted to perform '{action}'",
            )
        audit.log(
            "AUTH_SUCCESS",
            user_id=payload.get("sub"),
            details={"role": payload.get("role"), "action": action},
        )
        return payload

    return _dependency
