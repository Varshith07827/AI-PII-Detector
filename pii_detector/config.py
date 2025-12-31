"""Configuration and regex patterns for PII detection."""
from __future__ import annotations

import re
from typing import Dict, Pattern

# Sensitivity weights used for risk scoring
SENSITIVITY_WEIGHTS: Dict[str, int] = {"high": 3, "medium": 2, "low": 1}

# Regex patterns tuned for Indian context with general fallbacks
PII_PATTERNS: Dict[str, Pattern[str]] = {
    "aadhaar": re.compile(r"\b(?:[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4})\b"),
    "pan": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "passport": re.compile(r"\b[A-Z][0-9]{7}\b"),
    "credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "phone": re.compile(r"\b(?:\+?91[-\s]?)?(?:(?<!\d)([6-9][0-9]{2})[-\s]?(\d{3})[-\s]?(\d{4})(?!\d))\b"),
    "ip": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?\d?\d)(?:\.(?!$)|$)){4}\b"),
    "dob": re.compile(r"\b(?:0?[1-9]|[12][0-9]|3[01])[-/](?:0?[1-9]|1[0-2])[-/](?:19\d{2}|20\d{2})\b"),
    # Bank account: 9-18 digits with context keywords to avoid FP with phone/card
    "bank_account": re.compile(
        r"(?i)\b(?:acct|ac|account|a/c|a\\/?c\\/?|ac no\.?|account no\.?|a/c no\.?|act no\.?)[:#\s-]*([0-9]{9,18})\b"
    ),
    # IFSC validation: 4 letters, 0, 6 alnum
    "ifsc": re.compile(r"\b([A-Z]{4}0[0-9A-Z]{6})\b", re.IGNORECASE),
    # Generic Indian address cue (loose)
    "address": re.compile(r"\b(?:street|st\.|road|rd\.|nagar|colony|layout|phase|block|sector)\b", re.IGNORECASE),
    "person_name": re.compile(r"\b([A-Z][a-z]{2,}\s+[A-Z][a-z]{1,})\b"),
}

PLACEHOLDER_VALUES = {
    "0000000000",
    "1111111111",
    "1234567890",
    "9999999999",
    "ABCDE",
    "abcde",
    "XXXXX",
    "xxxxx",
    "N/A",
    "lorem ipsum",
    "test@example.com",
    "john doe",
    "a n other",
}

PLACEHOLDER_REGEXES = [
    re.compile(r"\bX{4,}\b", re.IGNORECASE),
    re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    re.compile(r"\b(?:1111|2222|3333|4444|5555|6666|7777|8888|9999){2,}\b"),
    re.compile(r"\b(?:aaa|bbb|ccc|ddd|eee|fff|ggg|hhh|iii|jjj|kkk|lll|mmm|nnn|ooo|ppp|qqq|rrr|sss|ttt|uuu|vvv|www|xxx|yyy|zzz){2,}\b", re.IGNORECASE),
    re.compile(r"\bplaceholder\b", re.IGNORECASE),
]

SPACY_MODEL_PREFERENCE = ["en_core_web_md", "en_core_web_sm"]

DEFAULT_MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
