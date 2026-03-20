"""Sensitive Value Registry — auto-extracts sensitive data from the knowledge base
and matches it against LLM output for intelligent redaction.

This is a deterministic, zero-API-call approach: at startup, extract every
sensitive value from the documents, then at filter time, match the output
against this registry using exact, fuzzy, and number-word matching.
"""

import json
import logging
import os
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

# Path to the knowledge base documents
_DOCUMENTS_DIR = os.path.join(
    os.path.dirname(__file__), "..", "agent", "documents"
)


@dataclass
class Finding:
    """A single sensitive value match found in text."""
    category: str
    matched_text: str
    registry_value: str
    replacement: str


class SensitiveValueRegistry:
    """Holds all sensitive values extracted from the knowledge base."""

    def __init__(self, config: dict):
        self.config = config
        self.replacements: Dict[str, str] = config.get("category_replacements", {})
        self.fuzzy_threshold: float = config.get("fuzzy_threshold", 0.8)
        self.number_proximity_pct: float = config.get("number_proximity_pct", 15)
        self.min_value_length: int = config.get("min_value_length", 3)

        # Registry: category -> set of string values
        self.registry: Dict[str, Set[str]] = {}

        # Numeric registry: category -> set of float values (for number-word matching)
        self.numeric_registry: Dict[str, Set[float]] = {}

        self._build()

    def _add(self, category: str, value: str) -> None:
        """Add a string value to the registry."""
        value = value.strip()
        if len(value) < self.min_value_length:
            return
        self.registry.setdefault(category, set()).add(value)

    def _add_numeric(self, category: str, value: float) -> None:
        """Add a numeric value to the numeric registry."""
        self.numeric_registry.setdefault(category, set()).add(value)

    def _build(self) -> None:
        """Extract sensitive values from all knowledge base documents."""
        self._extract_from_users_json()
        self._extract_from_financial_docs()
        self._extract_from_fraud_policy()
        self._extract_from_aml_policy()
        self._extract_from_legal_docs()
        self._extract_from_loan_docs()

        total = sum(len(v) for v in self.registry.values())
        logger.info("Sensitive registry built: %d values across %d categories",
                     total, len(self.registry))

    # ── Extractors ──────────────────────────────────────────────

    def _extract_from_users_json(self) -> None:
        """Extract PII from all 50 user profiles."""
        path = os.path.join(_DOCUMENTS_DIR, "user", "users.json")
        if not os.path.exists(path):
            return

        with open(path, encoding="utf-8") as f:
            users = json.load(f)

        for user in users:
            # Full names
            name = user.get("name", "")
            if name:
                self._add("USER_PII", name)
                # Also add first and last name separately
                parts = name.split()
                for part in parts:
                    if len(part) >= 3:
                        self._add("USER_PII", part)

            # Emails
            email = user.get("email", "")
            if email:
                self._add("USER_PII", email)

            # Phones
            phone = user.get("phone", "")
            if phone:
                self._add("USER_PII", phone)

            # User IDs
            uid = user.get("user_id", "")
            if uid:
                self._add("USER_ID", uid)

            # Balances
            balance = user.get("balance", "")
            if balance:
                self._add("FINANCIAL_ACCOUNT_DATA", str(balance))
                try:
                    self._add_numeric("FINANCIAL_ACCOUNT_DATA", float(balance))
                except (ValueError, TypeError):
                    pass

            # Risk scores
            risk = user.get("risk_score")
            if risk is not None:
                self._add("RISK_SCORE", str(risk))
                try:
                    self._add_numeric("RISK_SCORE", float(risk))
                except (ValueError, TypeError):
                    pass

    def _extract_from_financial_docs(self) -> None:
        """Extract dollar amounts from balance sheet and income statement."""
        for fname in ("balance_sheet.md", "income_statement.md"):
            path = os.path.join(_DOCUMENTS_DIR, "financial_docs", fname)
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as f:
                content = f.read()

            # Extract dollar amounts like $500,000 or $1,200,000
            for match in re.finditer(r"\$[\d,]+(?:\.\d+)?", content):
                val_str = match.group()
                self._add("CORPORATE_FINANCIAL", val_str)
                # Also store the raw number
                raw = val_str.replace("$", "").replace(",", "")
                try:
                    self._add_numeric("CORPORATE_FINANCIAL", float(raw))
                except ValueError:
                    pass

            # Extract percentage amounts
            for match in re.finditer(r"\d+(?:\.\d+)?%", content):
                self._add("CORPORATE_FINANCIAL", match.group())

    def _extract_from_fraud_policy(self) -> None:
        """Extract fraud detection thresholds."""
        path = os.path.join(_DOCUMENTS_DIR, "ai_fraud_detection", "fraud_detection_policy.md")
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as f:
            content = f.read()

        # Threshold values
        for match in re.finditer(r"(?:>|<)?\s*0\.\d+", content):
            val = match.group().strip().lstrip(">< ")
            self._add("SECURITY_THRESHOLD", val)
            try:
                self._add_numeric("SECURITY_THRESHOLD", float(val))
            except ValueError:
                pass

        # Model type info
        self._add("SECURITY_THRESHOLD", "Gradient Boosting")
        self._add("SECURITY_THRESHOLD", "Neural Network")

    def _extract_from_aml_policy(self) -> None:
        """Extract AML compliance thresholds."""
        path = os.path.join(_DOCUMENTS_DIR, "compliance_and_regulatory_docs", "aml_policy.md")
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as f:
            content = f.read()

        for match in re.finditer(r"\$[\d,]+", content):
            val_str = match.group()
            self._add("COMPLIANCE_THRESHOLD", val_str)
            raw = val_str.replace("$", "").replace(",", "")
            try:
                self._add_numeric("COMPLIANCE_THRESHOLD", float(raw))
            except ValueError:
                pass

    def _extract_from_legal_docs(self) -> None:
        """Extract registration numbers, addresses, share capital from legal docs."""
        path = os.path.join(
            _DOCUMENTS_DIR, "legal_and_foundaltional_docs", "certificate_of_incorporation.md"
        )
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as f:
            content = f.read()

        # Registration number
        reg_match = re.search(r"FN-\d{4}-\d+", content)
        if reg_match:
            self._add("LEGAL_DATA", reg_match.group())

        # Registered address
        addr_match = re.search(r"\d+ .+Street.+USA", content)
        if addr_match:
            self._add("LEGAL_DATA", addr_match.group())

        # Share capital
        for match in re.finditer(r"[\d,]+ shares", content):
            self._add("LEGAL_DATA", match.group())

        # Extract dollar amounts from legal docs
        for match in re.finditer(r"\$[\d,]+(?:\.\d+)?", content):
            val_str = match.group()
            self._add("LEGAL_DATA", val_str)

    def _extract_from_loan_docs(self) -> None:
        """Extract loan terms — amounts, rates, borrower names."""
        path = os.path.join(
            _DOCUMENTS_DIR, "customer_and_product_docs", "loan_aggrement.md"
        )
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as f:
            content = f.read()

        # Borrower name
        borrower_match = re.search(r"Borrower:\s*(.+)", content)
        if borrower_match:
            self._add("LOAN_DATA", borrower_match.group(1).strip())

        # Dollar amounts
        for match in re.finditer(r"\$[\d,]+(?:\.\d+)?", content):
            val_str = match.group()
            self._add("LOAN_DATA", val_str)
            raw = val_str.replace("$", "").replace(",", "")
            try:
                self._add_numeric("LOAN_DATA", float(raw))
            except ValueError:
                pass

        # Percentages
        for match in re.finditer(r"\d+(?:\.\d+)?%", content):
            self._add("LOAN_DATA", match.group())

    # ── Scanning ────────────────────────────────────────────────

    def scan_text(self, text: str) -> List[Finding]:
        """Scan text against the registry and return all sensitive matches."""
        findings: List[Finding] = []
        text_lower = text.lower()

        # Pass 1: Exact case-insensitive match
        for category, values in self.registry.items():
            replacement = self.replacements.get(category, "[REDACTED]")
            for value in values:
                if len(value) < self.min_value_length:
                    continue

                # For short values (< 5 chars), require word boundary match
                if len(value) < 5:
                    pattern = re.compile(r"\b" + re.escape(value) + r"\b", re.IGNORECASE)
                    match = pattern.search(text)
                    if match:
                        findings.append(Finding(
                            category=category,
                            matched_text=match.group(),
                            registry_value=value,
                            replacement=replacement,
                        ))
                else:
                    val_lower = value.lower()
                    idx = text_lower.find(val_lower)
                    if idx != -1:
                        matched = text[idx : idx + len(value)]
                        findings.append(Finding(
                            category=category,
                            matched_text=matched,
                            registry_value=value,
                            replacement=replacement,
                        ))

        # Pass 2: Number-word conversion
        findings.extend(self._scan_number_words(text))

        # Pass 3: Fuzzy match for longer values (names, addresses)
        findings.extend(self._scan_fuzzy(text))

        # Deduplicate by matched_text
        seen = set()
        unique = []
        for f in findings:
            key = (f.category, f.matched_text.lower())
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _scan_number_words(self, text: str) -> List[Finding]:
        """Convert written-out numbers to digits and match against numeric registry."""
        findings = []
        try:
            from word2number import w2n
        except ImportError:
            return findings

        # Extract potential number-word phrases from text
        # Look for sequences of number words
        number_words = (
            r"(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|"
            r"eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|"
            r"eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|"
            r"eighty|ninety|hundred|thousand|million|billion|half|quarter|"
            r"point|and|a)\b"
        )
        # Find sequences of 2+ number words
        pattern = re.compile(
            r"\b(" + number_words + r"(?:\s+" + number_words + r")*)",
            re.IGNORECASE,
        )

        for match in pattern.finditer(text):
            phrase = match.group().strip()
            if len(phrase.split()) < 2:
                continue  # Skip single words to reduce false positives

            # Handle "half a million" etc.
            phrase_for_conversion = phrase.lower()
            multiplier = 1.0
            if "half" in phrase_for_conversion:
                phrase_for_conversion = phrase_for_conversion.replace("half a ", "").replace("half ", "")
                multiplier = 0.5
            if "quarter" in phrase_for_conversion:
                phrase_for_conversion = phrase_for_conversion.replace("quarter of a ", "").replace("quarter ", "")
                multiplier = 0.25

            try:
                num_value = float(w2n.word_to_num(phrase_for_conversion)) * multiplier
            except (ValueError, IndexError):
                continue

            # Check against all numeric registries
            proximity = self.number_proximity_pct / 100.0
            for category, nums in self.numeric_registry.items():
                replacement = self.replacements.get(category, "[REDACTED]")
                for known_num in nums:
                    if known_num == 0:
                        continue
                    diff = abs(num_value - known_num) / abs(known_num)
                    if diff <= proximity:
                        findings.append(Finding(
                            category=category,
                            matched_text=match.group(),
                            registry_value=str(known_num),
                            replacement=replacement,
                        ))
                        break  # One match per phrase per category is enough

        return findings

    def _scan_fuzzy(self, text: str) -> List[Finding]:
        """Fuzzy match longer registry values (names, addresses) against text."""
        findings = []

        # Only fuzzy-match for categories where values are long enough
        fuzzy_categories = {"USER_PII", "LEGAL_DATA", "LOAN_DATA"}

        for category in fuzzy_categories:
            values = self.registry.get(category, set())
            replacement = self.replacements.get(category, "[REDACTED]")

            for value in values:
                if len(value) < 6:
                    continue  # Too short for meaningful fuzzy match

                # Skip if already found by exact match
                if value.lower() in text.lower():
                    continue

                # Sliding window fuzzy match
                val_len = len(value)
                for i in range(len(text) - val_len + 1):
                    window = text[i : i + val_len]
                    ratio = SequenceMatcher(None, value.lower(), window.lower()).ratio()
                    if ratio >= self.fuzzy_threshold:
                        findings.append(Finding(
                            category=category,
                            matched_text=window,
                            registry_value=value,
                            replacement=replacement,
                        ))
                        break  # One match per value is enough

        return findings


# ── Lazy singleton ──────────────────────────────────────────────

_registry: SensitiveValueRegistry | None = None


def get_registry(config: dict | None = None) -> SensitiveValueRegistry:
    """Return a cached registry, building it on first call."""
    global _registry
    if _registry is None:
        if config is None:
            config = {}
        _registry = SensitiveValueRegistry(config)
    return _registry
