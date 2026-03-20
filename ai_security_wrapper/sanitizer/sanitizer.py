"""
Layer 3 — Input Sanitizer
Detects prompt injection across multiple categories, validates schema,
enforces length limits. Reads configuration from config/sanitizer_enriched.yaml.
"""

import os
import re
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

from ai_security_wrapper.audit.logger import audit


def _load_config() -> dict:
    config_path = os.path.join(
        os.path.dirname(__file__), "..", "config", "sanitizer_enriched.yaml"
    )
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


CONFIG = _load_config()
SAN_CFG = CONFIG["sanitizer"]

# Collect all injection patterns from all enabled categories
INJECTION_CATEGORIES = [
    "direct_instruction_override",
    "persona_hijacking",
    "context_manipulation",
    "system_prompt_extraction",
    "indirect_injection_markers",
    "roleplay_framing",
    "harmful_content",
    "agentic_misuse",
    "data_extraction",
    "multilingual",
    "code_injection",
]

# Build a list of (compiled_pattern, category_name) tuples
INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = []
for cat_name in INJECTION_CATEGORIES:
    cat_cfg = SAN_CFG.get(cat_name, {})
    if not cat_cfg.get("enabled", False):
        continue
    patterns = cat_cfg.get("patterns", []) + cat_cfg.get("known_multilingual_patterns", [])
    for p in patterns:
        INJECTION_PATTERNS.append((re.compile(re.escape(p), re.IGNORECASE), cat_name))

# Also compile regex-based delimiter injection patterns
delimiter_cfg = SAN_CFG.get("delimiter_injection", {})
if delimiter_cfg.get("enabled", False):
    for p in delimiter_cfg.get("regex_patterns", []):
        try:
            INJECTION_PATTERNS.append((re.compile(p, re.IGNORECASE), "delimiter_injection"))
        except re.error:
            pass

MAX_LEN = SAN_CFG.get("max_input_length", 4000)
MIN_LEN = SAN_CFG.get("min_input_length", 1)
SCHEMA_CFG = SAN_CFG.get("schema", {})
MAX_CONTEXT = SCHEMA_CFG.get("max_context_items", 20)


class AgentRequest(BaseModel):
    """
    Validated schema for all incoming agent requests.
    Extend this model with fields your agent needs.
    """

    message: str = Field(..., min_length=1, max_length=4000, description="User message to the agent")
    session_id: Optional[str] = Field(None, max_length=128)
    context: Optional[List[Dict[str, Any]]] = Field(None, max_length=20)
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("message")
    @classmethod
    def no_injection(cls, v: str) -> str:
        lower = v.lower()
        for pattern, category in INJECTION_PATTERNS:
            if pattern.search(lower):
                raise ValueError(
                    f"Potential prompt injection detected (category: {category}): matched pattern '{pattern.pattern}'"
                )
        return v

    @field_validator("message")
    @classmethod
    def length_check(cls, v: str) -> str:
        if len(v) < MIN_LEN:
            raise ValueError(f"Message too short (min {MIN_LEN} chars)")
        if len(v) > MAX_LEN:
            raise ValueError(f"Message too long (max {MAX_LEN} chars)")
        return v

    @field_validator("context")
    @classmethod
    def context_size(cls, v):
        if v and len(v) > MAX_CONTEXT:
            raise ValueError(f"Context exceeds max items ({MAX_CONTEXT})")
        return v


class SanitizationResult(BaseModel):
    clean_request: AgentRequest
    warnings: List[str] = []


def sanitize(raw: dict, user_id: str = "anonymous", trace_id: str = "") -> SanitizationResult:
    """
    Validate and sanitize a raw request dictionary.
    Raises ValueError on hard violations.
    Returns SanitizationResult with a clean AgentRequest.
    """
    warnings = []
    preview_chars = SAN_CFG.get("logging", {}).get("raw_input_preview_chars", 200)

    try:
        clean = AgentRequest(**raw)
    except Exception as e:
        err_str = str(e)
        if "injection" in err_str.lower():
            audit.log(
                "INJECTION_DETECTED",
                user_id=user_id,
                trace_id=trace_id,
                details={
                    "error": err_str,
                    "message_preview_chars_50": raw.get("message", "")[:50],
                },
                level="WARNING",
            )
        else:
            audit.log(
                "SCHEMA_VIOLATION",
                user_id=user_id,
                trace_id=trace_id,
                details={"layer": "sanitizer", "violation_type": "validation_error", "value_preview": err_str[:preview_chars]},
            )
        raise ValueError(err_str)

    audit.log(
        "REQUEST_RECEIVED",
        user_id=user_id,
        trace_id=trace_id,
        details={"message_length": len(clean.message), "has_context": bool(clean.context)},
    )

    return SanitizationResult(clean_request=clean, warnings=warnings)
