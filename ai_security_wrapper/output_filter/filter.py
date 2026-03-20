"""
Layer 5 — Output Filter
PII redaction, secret detection, policy enforcement on agent responses.
Reads configuration from config/output_filter.yaml.
"""

import os
import re
from dataclasses import dataclass, field
from typing import List

import yaml
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from ai_security_wrapper.audit.logger import audit


def _load_config() -> dict:
    config_path = os.path.join(
        os.path.dirname(__file__), "..", "config", "output_filter.yaml"
    )
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


CONFIG = _load_config()
OF_CFG = CONFIG["output_filter"]
PII_CFG = OF_CFG.get("pii_detection", {})
POLICY_CFG = OF_CFG.get("content_policy", {})
CUSTOM_CFG = OF_CFG.get("custom_recognizers", {})
REGISTRY_CFG = OF_CFG.get("sensitive_registry", {})

# Presidio engines (loaded once at import time)
_analyzer = AnalyzerEngine()
_anonymizer = AnonymizerEngine()

# Register custom recognizers from config
if CUSTOM_CFG.get("enabled"):
    for rec in CUSTOM_CFG.get("recognizers", []):
        if rec.get("action") == "flag":
            continue
        try:
            pattern = Pattern(
                name=rec["name"],
                regex=rec["pattern"],
                score=rec.get("score", 0.9),
            )
            recognizer = PatternRecognizer(
                supported_entity=rec["label"],
                patterns=[pattern],
            )
            _analyzer.registry.add_recognizer(recognizer)
        except Exception:
            pass

# Build per-entity config from the enriched YAML (now a dict, not a list)
PII_ENTITIES_CFG = PII_CFG.get("entities", {})

# Merge custom recognizer entities into the PII config for scanning + anonymization
if CUSTOM_CFG.get("enabled"):
    for rec in CUSTOM_CFG.get("recognizers", []):
        if rec.get("action") != "flag" and rec["label"] not in PII_ENTITIES_CFG:
            PII_ENTITIES_CFG[rec["label"]] = {
                "action": rec.get("action", "redact"),
                "score_threshold": rec.get("score", 0.9),
                "replacement": rec.get("replacement", "[REDACTED]"),
            }

# Entity names for Presidio analysis
PII_ENTITY_NAMES = list(PII_ENTITIES_CFG.keys())
PII_DEFAULT_REPLACEMENT = PII_CFG.get("default_replacement", "[REDACTED]")
EMAIL_ALLOWLIST = [e.lower() for e in PII_CFG.get("email_allowlist", [])]
MAX_OUT_LEN = OF_CFG.get("max_output_length", 8000)
TRUNCATION_SUFFIX = OF_CFG.get("truncation_suffix", "\n\n[Response truncated by output policy]")

# Compile secret regex patterns
_SECRET_PATTERNS = []
for item in OF_CFG.get("secret_patterns", []):
    try:
        _SECRET_PATTERNS.append((re.compile(item["pattern"]), item["label"], item.get("action", "redact")))
    except re.error:
        pass

_POLICY_TOPICS = [t.lower() for t in POLICY_CFG.get("blocked_topics", [])]

# Compile policy regex patterns
_POLICY_REGEX = []
for p in POLICY_CFG.get("blocked_regex_patterns", []):
    try:
        _POLICY_REGEX.append(re.compile(p, re.IGNORECASE))
    except re.error:
        pass


@dataclass
class FilterResult:
    filtered_text: str
    pii_found: bool = False
    secrets_found: List[str] = field(default_factory=list)
    policy_violations: List[str] = field(default_factory=list)
    truncated: bool = False
    registry_findings: List[str] = field(default_factory=list)


def filter_output(
    text: str,
    user_id: str = "anonymous",
    trace_id: str = "",
) -> FilterResult:
    """
    Apply all output filters to agent response text.
    Returns a FilterResult with the safe text and a report of what was found.
    """
    result = FilterResult(filtered_text=text)
    should_block = False

    # 1. Truncate if too long
    if len(text) > MAX_OUT_LEN:
        text = text[:MAX_OUT_LEN] + TRUNCATION_SUFFIX
        result.truncated = True
        audit.log(
            "RESPONSE_TRUNCATED",
            user_id=user_id,
            trace_id=trace_id,
            details={"original_length": len(result.filtered_text), "truncated_to": MAX_OUT_LEN},
        )

    # 1.5 Protect allowlisted emails from redaction
    _email_placeholders = {}
    for i, allowed_email in enumerate(EMAIL_ALLOWLIST):
        placeholder = f"__ALLOWED_EMAIL_{i}__"
        # Case-insensitive replacement — preserve original casing
        pattern_re = re.compile(re.escape(allowed_email), re.IGNORECASE)
        match = pattern_re.search(text)
        if match:
            _email_placeholders[placeholder] = match.group()
            text = pattern_re.sub(placeholder, text)

    # 2. Secret pattern redaction
    for pattern, label, action in _SECRET_PATTERNS:
        if pattern.search(text):
            if action == "block_response":
                should_block = True
                result.secrets_found.append(label)
            else:
                text = pattern.sub(f"[{label.upper().replace(' ', '_')}_REDACTED]", text)
                result.secrets_found.append(label)

    if result.secrets_found:
        audit.log(
            "SECRET_REDACTED",
            user_id=user_id,
            trace_id=trace_id,
            details={"secret_type": result.secrets_found},
            level="WARNING",
        )

    if should_block:
        result.filtered_text = "[Response blocked — sensitive credentials detected]"
        return result

    # 3. PII redaction via Presidio
    if PII_CFG.get("enabled"):
        # Build per-entity score thresholds — use entity-level threshold or fall back
        entity_names_to_scan = []
        min_threshold = 1.0
        for entity_name, entity_cfg in PII_ENTITIES_CFG.items():
            entity_action = entity_cfg.get("action", "redact")
            if entity_action in ("redact", "mask", "hash", "block_response"):
                entity_names_to_scan.append(entity_name)
                threshold = entity_cfg.get("score_threshold", 0.7)
                if threshold < min_threshold:
                    min_threshold = threshold

        if entity_names_to_scan:
            analysis = _analyzer.analyze(
                text=text,
                entities=entity_names_to_scan,
                language=PII_CFG.get("language", "en"),
                score_threshold=min_threshold,
            )

            if analysis:
                # Filter results by per-entity thresholds
                filtered_analysis = []
                for r in analysis:
                    entity_cfg = PII_ENTITIES_CFG.get(r.entity_type, {})
                    entity_threshold = entity_cfg.get("score_threshold", 0.7)
                    if r.score >= entity_threshold:
                        filtered_analysis.append(r)
                        # Check if this entity should block the entire response
                        if entity_cfg.get("action") == "block_response":
                            should_block = True

                if should_block:
                    audit.log(
                        "PII_REDACTED",
                        user_id=user_id,
                        trace_id=trace_id,
                        details={"entity_types": [r.entity_type for r in filtered_analysis], "entity_count": len(filtered_analysis)},
                    )
                    result.pii_found = True
                    result.filtered_text = "[Response blocked — sensitive PII detected]"
                    return result

                if filtered_analysis:
                    # Build per-entity operators with entity-specific replacements
                    operators = {}
                    for entity_name, entity_cfg in PII_ENTITIES_CFG.items():
                        replacement = entity_cfg.get("replacement", PII_DEFAULT_REPLACEMENT)
                        operators[entity_name] = OperatorConfig("replace", {"new_value": replacement})

                    anonymized = _anonymizer.anonymize(
                        text=text,
                        analyzer_results=filtered_analysis,
                        operators=operators,
                    )
                    text = anonymized.text
                    result.pii_found = True
                    audit.log(
                        "PII_REDACTED",
                        user_id=user_id,
                        trace_id=trace_id,
                        details={"entity_types": list(set(r.entity_type for r in filtered_analysis)), "entity_count": len(filtered_analysis)},
                    )

    # 3.5 Sensitive Value Registry scan (knowledge-base-aware redaction)
    if REGISTRY_CFG.get("enabled"):
        try:
            from ai_security_wrapper.output_filter.sensitive_registry import get_registry
            registry = get_registry(REGISTRY_CFG)
            findings = registry.scan_text(text)
            for finding in findings:
                text = text.replace(finding.matched_text, finding.replacement)
                if finding.category not in result.registry_findings:
                    result.registry_findings.append(finding.category)
            if findings:
                result.pii_found = True
                audit.log(
                    "SENSITIVE_REGISTRY_MATCH",
                    user_id=user_id,
                    trace_id=trace_id,
                    details={
                        "categories": result.registry_findings,
                        "finding_count": len(findings),
                    },
                )
        except Exception as e:
            audit.log(
                "SENSITIVE_REGISTRY_ERROR",
                user_id=user_id,
                trace_id=trace_id,
                details={"error": str(e)[:200]},
                level="WARNING",
            )

    # 4. Policy topic check (keyword)
    lower = text.lower()
    for topic in _POLICY_TOPICS:
        if topic in lower:
            result.policy_violations.append(topic)

    # 5. Policy regex check
    for regex in _POLICY_REGEX:
        if regex.search(text):
            result.policy_violations.append(f"regex:{regex.pattern[:50]}")

    if result.policy_violations:
        audit.log(
            "POLICY_VIOLATION",
            user_id=user_id,
            trace_id=trace_id,
            details={"violation_type": "content_policy", "topic": result.policy_violations},
            level="WARNING",
        )
        text = "[Response blocked by output policy filter]"

    # Restore allowlisted emails
    for placeholder, original in _email_placeholders.items():
        text = text.replace(placeholder, original)

    result.filtered_text = text
    return result
