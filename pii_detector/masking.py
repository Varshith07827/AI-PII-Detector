"""Masking and synthetic replacement utilities."""
from __future__ import annotations

import itertools
from typing import List

from .detection import Entity


FULL_TOKENS = {
    "email": "[EMAIL]",
    "phone": "[PHONE]",
    "credit_card": "[CARD]",
    "bank_account": "[BANK_ACCOUNT]",
    "aadhaar": "[AADHAAR]",
    "pan": "[PAN]",
    "passport": "[PASSPORT]",
    "person_name": "[NAME]",
    "address": "[ADDRESS]",
    "placeholder": "[PLACEHOLDER]",
}


def mask_value(value: str, label: str, mode: str) -> str:
    if mode == "partial":
        if label in {"credit_card", "bank_account", "aadhaar"}:
            return _mask_digits_keep_tail(value, 4)
        if label == "phone":
            return _mask_digits_keep_tail(value, 3)
        if label == "email":
            return _mask_email(value)
        return _generic_mask(value, label)
    if mode == "synthetic":
        return _synthetic(value, label)
    return _generic_mask(value, label)


def apply_masks(
    text: str,
    entities: List[Entity],
    mode: str = "full",
    include_placeholders: bool = False,
    allowed_labels: List[str] | None = None,
) -> str:
    # Apply masks from end to start to keep offsets stable
    sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
    masked = text
    for ent in sorted_entities:
        if allowed_labels and ent.label not in allowed_labels:
            continue
        if ent.placeholder and not include_placeholders:
            continue
        replacement = mask_value(ent.value, ent.label, mode)
        masked = masked[: ent.start] + replacement + masked[ent.end :]
    return masked


def _mask_digits_keep_tail(value: str, keep: int) -> str:
    # Preserve separators and length; keep last N digits, mask other digits with '*'
    out_chars = []
    digits_seen = 0
    for ch in reversed(value):
        if ch.isdigit():
            digits_seen += 1
            if digits_seen <= keep:
                out_chars.append(ch)
            else:
                out_chars.append("*")
        else:
            out_chars.append(ch)
    return "".join(reversed(out_chars))


def _mask_email(value: str) -> str:
    if "@" not in value:
        return _generic_mask(value, "email")
    user, domain = value.split("@", 1)
    masked_user = user[:1] + "***" if user else "***"
    return f"{masked_user}@{domain}"


def _generic_mask(value: str, label: str | None = None) -> str:
    if label and label in FULL_TOKENS:
        return FULL_TOKENS[label]
    return "[REDACTED]"


def _synthetic(value: str, label: str) -> str:
    counter = next(_synthetic_counter)
    if label == "credit_card":
        return _synthetic_card(counter, value)
    if label == "bank_account":
        return _synthetic_bank_account(counter, value)
    if label == "aadhaar":
        return _synthetic_aadhaar(counter)
    if label == "pan":
        return _synthetic_pan(counter)
    if label == "passport":
        return _synthetic_passport(counter)
    if label == "phone":
        return _synthetic_phone(counter)
    if label == "email":
        return _synthetic_email(counter, value)
    if label == "person_name":
        return f"Person {counter:03d}"
    if label == "address":
        return f"Address {counter:03d}"
    if label == "placeholder":
        return f"PH_{counter:04d}"
    prefix = label.upper()
    return f"SYN_{prefix}_{counter}"


_synthetic_counter = itertools.count(1)


def _synthetic_card(counter: int, original: str) -> str:
    # Generate a 16-digit Luhn-valid number, keep grouping if present in original
    digits_needed = 15
    base = "4" + _pad_digits(counter, digits_needed - 1)
    check = _luhn_check_digit(base)
    number = base + check
    return _regroup_like_original(number, original)


def _synthetic_bank_account(counter: int, original: str) -> str:
    length = max(9, min(18, sum(ch.isdigit() for ch in original) or 12))
    digits = _pad_digits(counter, length)
    return _regroup_like_original(digits, original)


def _synthetic_aadhaar(counter: int) -> str:
    body = _pad_digits(counter, 11)
    first = str(2 + (counter % 8))  # 2-9
    return first + body


def _synthetic_pan(counter: int) -> str:
    prefix = "ABCDE"
    middle = _pad_digits(counter, 4)
    suffix = chr(ord("A") + (counter % 26))
    return prefix + middle + suffix


def _synthetic_passport(counter: int) -> str:
    prefix = chr(ord("M") + (counter % 10))
    return prefix + _pad_digits(counter, 7)


def _synthetic_phone(counter: int) -> str:
    tail = _pad_digits(counter, 9)
    return f"+91-9{tail}"


def _synthetic_email(counter: int, original: str) -> str:
    domain = "example.in"
    if "@" in original:
        domain = original.split("@", 1)[1] or domain
    return f"user{counter:04d}@{domain}"


def _pad_digits(counter: int, length: int) -> str:
    s = str(counter).rjust(length, "0")
    if len(s) > length:
        s = s[-length:]
    return s


def _luhn_check_digit(number_without_check: str) -> str:
    digits = [int(d) for d in number_without_check]
    digits.reverse()
    total = 0
    for idx, d in enumerate(digits):
        if idx % 2 == 0:
            d = d * 2
            if d > 9:
                d -= 9
        total += d
    check = (10 - (total % 10)) % 10
    return str(check)


def _regroup_like_original(synth: str, original: str) -> str:
    # Preserve separators from the original; replace digit slots with synthetic digits in order.
    digits_iter = iter(synth)
    rebuilt = []
    for ch in original:
        if ch.isdigit():
            rebuilt.append(next(digits_iter, ""))
        else:
            rebuilt.append(ch)
    # Append any remaining digits (if original had fewer digits than synth)
    rebuilt.append("".join(digits_iter))
    candidate = "".join(rebuilt)
    # Fallback to plain synth if we ended up empty (e.g., original had no digits)
    return candidate if any(c.isdigit() for c in candidate) else synth
