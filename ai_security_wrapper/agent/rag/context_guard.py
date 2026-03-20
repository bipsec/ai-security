"""Context Guard — sanitize retrieved chunks BEFORE they reach the LLM.

If the LLM never sees sensitive data, it cannot leak it — regardless of
any prompt injection, creative phrasing, or rule contradiction.

Each document chunk has a 'category' metadata field set by document_loader.py.
The guard applies per-category redaction policies: heavy, medium, light, or pass.
"""

import re
from typing import Dict, List, Set

from langchain_core.documents import Document


# ── Category-specific redactors ─────────────────────────────────────

def _redact_user_data(text: str) -> str:
    """HEAVY: Redact PII fields from user profile chunks.

    document_loader.py creates user chunks in this exact format:
        User Profile - Alice Johnson (U001)
        Email: alice.johnson@example.com | Phone: +1-555-1001
        KYC Status: verified | Risk Score: 0.12 | Balance: 5230.50 USD
        Account Status: active | Country: USA | Created: 2026-01-01T10:00:00Z
    """
    # Redact email
    text = re.sub(r"Email:\s*\S+", "Email: [REDACTED]", text)
    # Redact phone
    text = re.sub(r"Phone:\s*[\+\d\-]+", "Phone: [REDACTED]", text)
    # Redact balance
    text = re.sub(r"Balance:\s*[\d,\.]+\s*\w{0,3}", "Balance: [REDACTED]", text)
    # Redact risk score
    text = re.sub(r"Risk Score:\s*[\d\.]+", "Risk Score: [REDACTED]", text)
    # Redact KYC status
    text = re.sub(r"KYC Status:\s*\w+", "KYC Status: [REDACTED]", text)
    # Redact account status
    text = re.sub(r"Account Status:\s*\w+", "Account Status: [REDACTED]", text)
    # Redact creation date
    text = re.sub(r"Created:\s*[\dT:\-Z]+", "Created: [REDACTED]", text)
    # Redact user ID in parentheses
    text = re.sub(r"\(U\d{3}\)", "([REDACTED])", text)
    return text


def _redact_financial(text: str) -> str:
    """HEAVY: Redact all dollar amounts and percentages from financial docs."""
    # Dollar amounts: $500,000 or $1,200,000.00
    text = re.sub(r"\$[\d,]+(?:\.\d+)?", "[CONFIDENTIAL]", text)
    # Standalone large numbers that look like financial figures
    text = re.sub(r"\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b", "[CONFIDENTIAL]", text)
    # Percentages
    text = re.sub(r"\d+(?:\.\d+)?%", "[CONFIDENTIAL]", text)
    return text


def _redact_fraud_thresholds(text: str) -> str:
    """HEAVY: Redact fraud detection thresholds and model details."""
    # Threshold values like > 0.8, 0.5-0.8, < 0.5
    text = re.sub(r"[><]?\s*0\.\d+", "[THRESHOLD_REDACTED]", text)
    # Score ranges
    text = re.sub(r"\d\.\d+\s*[–\-]\s*\d\.\d+", "[THRESHOLD_REDACTED]", text)
    # Model type
    text = re.sub(r"(?i)gradient boosting", "[MODEL_REDACTED]", text)
    text = re.sub(r"(?i)neural network", "[MODEL_REDACTED]", text)
    return text


def _redact_compliance(text: str) -> str:
    """MEDIUM: Redact specific dollar thresholds from AML/KYC policies."""
    # Dollar thresholds
    text = re.sub(r"\$[\d,]+(?:\.\d+)?", "[THRESHOLD_REDACTED]", text)
    return text


def _redact_security(text: str) -> str:
    """MEDIUM: Redact encryption specs and specific implementation details."""
    text = re.sub(r"(?i)AES-256", "[ENCRYPTION_REDACTED]", text)
    text = re.sub(r"(?i)TLS\s*1\.\d\+?", "[ENCRYPTION_REDACTED]", text)
    return text


def _redact_legal(text: str) -> str:
    """MEDIUM: Redact registration numbers, addresses, share capital."""
    # Registration number
    text = re.sub(r"FN-\d{4}-\d+", "[REG_REDACTED]", text)
    # Address patterns
    text = re.sub(r"\d+\s+\w+\s+Street[^,\n]*(?:,\s*\w+)*(?:,\s*\w+)*(?:,\s*USA)?",
                  "[ADDRESS_REDACTED]", text)
    # Share capital
    text = re.sub(r"[\d,]+ shares", "[SHARES_REDACTED]", text)
    return text


def _redact_customer_docs(text: str) -> str:
    """LIGHT: Only redact specific borrower details from loan agreements."""
    # Borrower name from loan agreement
    text = re.sub(r"Borrower:\s*.+", "Borrower: [REDACTED]", text)
    # Loan-specific dollar amounts
    text = re.sub(r"\$[\d,]+(?:\.\d+)?", "[AMOUNT_REDACTED]", text)
    return text


def _redact_risk(text: str) -> str:
    """MEDIUM: Redact specific risk parameters and thresholds."""
    text = re.sub(r"\$[\d,]+(?:\.\d+)?", "[THRESHOLD_REDACTED]", text)
    text = re.sub(r"\d+(?:\.\d+)?%", "[THRESHOLD_REDACTED]", text)
    return text


# ── Policy registry ────────────────────────────────────────────────

CATEGORY_POLICIES: Dict[str, dict] = {
    "user_data":                       {"level": "heavy",  "redactor": _redact_user_data},
    "financial_docs":                  {"level": "heavy",  "redactor": _redact_financial},
    "ai_fraud_detection":              {"level": "heavy",  "redactor": _redact_fraud_thresholds},
    "compliance_and_regulatory_docs":  {"level": "medium", "redactor": _redact_compliance},
    "security_docs":                   {"level": "medium", "redactor": _redact_security},
    "legal_and_foundaltional_docs":    {"level": "medium", "redactor": _redact_legal},
    "customer_and_product_docs":       {"level": "light",  "redactor": _redact_customer_docs},
    "risk_and_management":             {"level": "medium", "redactor": _redact_risk},
    "faq":                             {"level": "pass",   "redactor": None},
    "general":                         {"level": "pass",   "redactor": None},
}


# ── Main function ──────────────────────────────────────────────────

def sanitize_context(docs: List[Document]) -> List[Document]:
    """Apply per-category redaction to retrieved documents before LLM sees them.

    Returns sanitized Document list with 'context_guard' metadata added.
    """
    sanitized = []
    for doc in docs:
        category = doc.metadata.get("category", "general")
        policy = CATEGORY_POLICIES.get(category, {"level": "pass", "redactor": None})
        redactor = policy.get("redactor")

        if redactor:
            new_content = redactor(doc.page_content)
            sanitized.append(Document(
                page_content=new_content,
                metadata={**doc.metadata, "context_guard": policy["level"]},
            ))
        else:
            sanitized.append(Document(
                page_content=doc.page_content,
                metadata={**doc.metadata, "context_guard": "pass"},
            ))

    return sanitized


def get_redacted_categories(raw_docs: List[Document], sanitized_docs: List[Document]) -> List[str]:
    """Compare raw and sanitized docs to find which categories were actually redacted."""
    categories: Set[str] = set()
    for raw, san in zip(raw_docs, sanitized_docs):
        if raw.page_content != san.page_content:
            categories.add(raw.metadata.get("category", "unknown"))
    return sorted(categories)
