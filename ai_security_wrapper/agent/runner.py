"""
Layer 4 — FinNova Financial Advisor Agent (RAG)
Reads configuration from config/agent.yaml.
Uses hybrid retrieval (ChromaDB + BM25 + RRF) with OpenRouter LLM.
"""

import os
from typing import Dict

import yaml

from ai_security_wrapper.audit.logger import audit
from ai_security_wrapper.sanitizer.sanitizer import AgentRequest


def _load_config() -> dict:
    config_path = os.path.join(
        os.path.dirname(__file__), "..", "config", "agent.yaml"
    )
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


CONFIG = _load_config()
AGENT_CFG = CONFIG.get("agent", {})
LIMITS_CFG = AGENT_CFG.get("limits", {})


def run(request: AgentRequest, user_id: str = "anonymous", trace_id: str = "") -> Dict:
    """
    Entry point called by the security pipeline.

    Returns:
        dict with keys:
            response: str — LLM response text
            raw_context: str — what retriever fetched (before context guard)
            sanitized_context: str — what LLM saw (after context guard)
            context_guard_applied: bool
            context_guard_categories: list[str] — categories redacted
    """
    audit.log(
        "AGENT_CALL",
        user_id=user_id,
        trace_id=trace_id,
        details={"message_length": len(request.message), "has_context": bool(request.context)},
    )

    if AGENT_CFG.get("mock_mode", False):
        mock_response = AGENT_CFG.get(
            "mock_response",
            "Agent response placeholder — connect your agent in ai_security_wrapper/agent/"
        )
        result = {
            "response": f"{mock_response}\n\n[Echo] You said: {request.message}",
            "raw_context": "",
            "sanitized_context": "",
            "context_guard_applied": False,
            "context_guard_categories": [],
        }
    else:
        from ai_security_wrapper.agent.rag.chain import invoke_with_context
        from ai_security_wrapper.agent.rag.indexer import get_retriever

        retriever = get_retriever()
        result = invoke_with_context(retriever, request.message, apply_guard=True)

    # Enforce max output length from agent config
    max_output = LIMITS_CFG.get("max_output_chars", 16000)
    if len(result["response"]) > max_output:
        result["response"] = result["response"][:max_output]

    audit.log(
        "AGENT_RESPONSE",
        user_id=user_id,
        trace_id=trace_id,
        details={"response_length": len(result["response"])},
    )

    return result
