"""Detection and risk scoring utilities for PII."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .config import (
    DEFAULT_MAX_FILE_SIZE_BYTES,
    PII_PATTERNS,
    PLACEHOLDER_REGEXES,
    PLACEHOLDER_VALUES,
    SENSITIVITY_WEIGHTS,
    SPACY_MODEL_PREFERENCE,
)

try:
    import spacy  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    spacy = None


@dataclass
class Entity:
    label: str
    start: int
    end: int
    value: str
    confidence: float
    sensitivity: str
    placeholder: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "label": self.label,
            "start": self.start,
            "end": self.end,
            "value": self.value,
            "confidence": round(self.confidence, 3),
            "sensitivity": self.sensitivity,
            "placeholder": self.placeholder,
        }


def _load_nlp_model():
    if not spacy:
        return None
    for model in SPACY_MODEL_PREFERENCE:
        try:
            return spacy.load(model)
        except Exception:
            continue
    return None


NLP = _load_nlp_model()


def _score_sensitivity(label: str) -> str:
    high = {"aadhaar", "passport", "credit_card", "pan", "bank_account"}
    medium = {"email", "phone", "ip", "dob"}
    if label in high:
        return "high"
    if label in medium:
        return "medium"
    return "low"


def detect_placeholders(text: str) -> List[Entity]:
    hits: List[Entity] = []
    lower_text = text.lower()
    for value in PLACEHOLDER_VALUES:
        idx = lower_text.find(value.lower())
        if idx != -1:
            hits.append(
                Entity(
                    label="placeholder",
                    start=idx,
                    end=idx + len(value),
                    value=text[idx : idx + len(value)],
                    confidence=0.4,
                    sensitivity="low",
                    placeholder=True,
                )
            )
    for regex in PLACEHOLDER_REGEXES:
        for m in regex.finditer(text):
            hits.append(
                Entity(
                    label="placeholder",
                    start=m.start(),
                    end=m.end(),
                    value=m.group(0),
                    confidence=0.4,
                    sensitivity="low",
                    placeholder=True,
                )
            )
    return hits


def detect_regex(text: str) -> List[Entity]:
    entities: List[Entity] = []
    for label, pattern in PII_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            # Bank account pattern captures digits in group 1
            if label == "bank_account" and match.lastindex:
                value = match.group(match.lastindex)
            sensitivity = _score_sensitivity(label)
            confidence = 0.7 if label != "person_name" else 0.4
            entities.append(
                Entity(
                    label=label,
                    start=match.start(),
                    end=match.end(),
                    value=value,
                    confidence=confidence,
                    sensitivity=sensitivity,
                )
            )
    entities.extend(detect_placeholders(text))
    return _deduplicate_entities(entities)


def detect_nlp(text: str) -> List[Entity]:
    if not NLP:
        return []
    doc = NLP(text)
    entities: List[Entity] = []
    for ent in doc.ents:
        label = None
        if ent.label_ in {"PERSON"}:
            label = "person_name"
        elif ent.label_ in {"GPE", "LOC"}:
            label = "address"
        elif ent.label_ in {"DATE"}:
            label = "dob"
        if label:
            entities.append(
                Entity(
                    label=label,
                    start=ent.start_char,
                    end=ent.end_char,
                    value=ent.text,
                    confidence=float(ent.score) if hasattr(ent, "score") else 0.55,
                    sensitivity=_score_sensitivity(label),
                )
            )
    return _deduplicate_entities(entities)


def detect_pii(text: str, mode: str = "hybrid") -> List[Entity]:
    regex_hits = detect_regex(text)
    if mode == "regex":
        return regex_hits
    nlp_hits = detect_nlp(text)
    combined = _deduplicate_entities(regex_hits + nlp_hits)
    return combined


def risk_score(entities: List[Entity]) -> Dict[str, object]:
    # Real-world risk scoring model
    # 1. Base Weights (Impact of a single occurrence)
    weights = {
        "aadhaar": 35, "pan": 25, "passport": 30, "credit_card": 35, "bank_account": 30,
        "email": 5, "phone": 10, "ip": 1, "dob": 5, "person_name": 2, "address": 5, "ifsc": 5
    }
    
    score = 0.0
    type_counts: Dict[str, int] = {}
    placeholder_count = 0
    unique_types = set()

    for ent in entities:
        if ent.placeholder:
            placeholder_count += 1
            continue 
        
        type_counts[ent.label] = type_counts.get(ent.label, 0) + 1
        unique_types.add(ent.label)
        
        # Diminishing returns for volume to simulate real-world exposure
        # 1st item: 100% impact
        # 2nd item: 50% impact (confirmation)
        # 3rd+ item: 10% impact (bulk data)
        count = type_counts[ent.label]
        w = weights.get(ent.label, 1)
        
        if count == 1:
            score += w
        elif count == 2:
            score += w * 0.5
        else:
            score += w * 0.1

    # 2. Critical Boosters (Presence of ANY high-risk item sets a floor)
    # Finding a single Credit Card or Aadhaar is immediately a high-risk event.
    critical_types = {"aadhaar", "credit_card", "passport", "bank_account"}
    if any(t in unique_types for t in critical_types):
        score = max(score, 65) 

    # 3. Combination Boosters (The "Trinity" effect)
    # Identity Theft Risk: Name + DOB + (Address OR Phone OR Email)
    has_identity = "person_name" in unique_types and "dob" in unique_types
    has_contact = any(t in unique_types for t in ["address", "phone", "email"])
    if has_identity and has_contact:
        score += 25
    
    # Financial Fraud Risk: (Card OR Bank) + Name
    has_financial = any(t in unique_types for t in ["credit_card", "bank_account"])
    if has_financial and "person_name" in unique_types:
        score += 20

    # 4. Normalization and Bucketing
    normalized = min(100, round(score))
    
    bucket = "low"
    if normalized >= 80:
        bucket = "critical"
    elif normalized >= 50:
        bucket = "high"
    elif normalized >= 20:
        bucket = "medium"
    
    compliance = {
        "gdpr": any(t in type_counts for t in ["person_name", "address", "email", "ip", "dob"]),
        "dpdp": any(t in type_counts for t in ["aadhaar", "phone", "email", "pan", "bank_account"]),
        "hipaa": any(t in type_counts for t in ["person_name", "address", "dob"]),
        "pci_dss": any(t in type_counts for t in ["credit_card"]),
    }

    return {
        "score": normalized,
        "bucket": bucket,
        "counts": type_counts,
        "placeholders": placeholder_count,
        "compliance": compliance,
    }


def _deduplicate_entities(entities: List[Entity]) -> List[Entity]:
    entities = sorted(entities, key=lambda e: (e.start, -(e.end - e.start)))
    pruned: List[Entity] = []
    for ent in entities:
        if any(_overlaps(ent, existing) for existing in pruned):
            continue
        pruned.append(ent)
    return pruned


def _overlaps(a: Entity, b: Entity) -> bool:
    return not (a.end <= b.start or b.end <= a.start)
