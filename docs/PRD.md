# Product Requirements Document: PII Detector – AI Privacy Protection Tool

## Overview
Offline-first tool that detects, visualizes, risk-scores, and masks PII from uploaded files or pasted text, plus a CLI for local/automated use. Runs locally with no cloud dependency or data retention.

## Goals
- Detect 11+ PII types with high precision/recall; process ≤10 MB files in <5s.
- Clear highlighting by sensitivity tier and a concise risk score with compliance hints (GDPR/DPDP/HIPAA).
- One-click masking: partial, full, synthetic; download sanitized output.
- Fully local execution; no external APIs; ephemeral in-memory processing.

## Target Users
- Students and developers cleaning samples/snippets.
- Security and compliance teams for pre-sharing checks.
- Operational staff sanitizing documents before email/upload.

## Key Features
- Multi-format ingest: PDF, DOCX, CSV, XLSX, TXT.
- Hybrid detection: regex + optional spaCy NLP (best available offline model preferred).
- CLI for headless/local workflows (text or file input, JSON output, masking selection).
- PII types: Aadhaar, Passport (IN), PAN, Credit/Debit Card, Bank Account, Email, Phone (+91/10-digit), IP, DOB, Person Name, Address/Location, Placeholder/Fake data.
- Heat-map highlighting by sensitivity (High/Medium/Low) and risk dashboard.
- Masking modes: partial, full, synthetic; placeholders masked only when opt-in.
- Offline-only, no logging of content, immediate deletion of temp data.

## Locale & Banking Focus (India)
- Strong emphasis on Indian IDs and phone formats.
- Bank accounts: regex for 9–18 digits with context terms (acct/ac/a/c etc.), SBI 11–17, ICICI/HDFC 12, PNB/BOB 14–16, cooperative 9–12; IFSC validation (4 letters + 0 + 6 alnum) boosts confidence; reject clashes with phone/card/Aadhaar when checks fail.

## Placeholder/Fake Detection
- Catch obvious dummies: repeated digits, sequential numbers, XXXX/abcd, placeholder words, lorem ipsum, test@example.com, John Doe/A N Other, N/A.
- Mark as placeholder/fake with low confidence; surface in risk summary; masking is opt-in.

## User Flow
1. Upload file or paste text.
2. System extracts content (in-memory).
3. Detect PII; highlight and show risk + compliance badges.
4. User selects masking mode and optional placeholder masking.
5. Download sanitized output (original format when feasible; TXT fallback).

## Functional Requirements
- Accept files ≤10 MB; reject with friendly error otherwise.
- Supported formats: PDF, DOCX, CSV, XLSX, TXT.
- Detection outputs spans with label, offsets, confidence, sensitivity, placeholder flag.
- Risk score: weighted sum with diminishing returns, critical floors for high-risk types, combo bonuses (identity + contact, financial + name); buckets Low/Medium/High/Critical; compliance flags for GDPR/DPDP/HIPAA/PCI-DSS.
- Masking: partial (keep tails), full ([REDACTED]/tokens), synthetic (type-consistent fakes with watermark prefix). Placeholders masked only if opt-in.
- API: POST /api/detect (multipart or JSON), POST /api/mask, GET /health.
- CLI: detect and mask from command line; supports detection mode (`regex`/`hybrid`), masking mode (`full`/`partial`/`synthetic`), optional JSON report, and output file.

## Non-Functional Requirements
- Python 3.8+; Flask REST API; optional spaCy (prefer medium model, fallback small); preload patterns/models to reduce cold starts.
- In-memory processing; minimal memory overhead (<2x file size typical).
- Offline execution; network calls disabled; CLI works fully offline.
- Basic accessibility: keyboard nav, sufficient contrast.
- Logging: operational only; no content; optional debug flag for troubleshooting (redacted).

## Performance Targets
- ≤5s end-to-end for 10 MB PDFs/CSVs on reference laptop.
- Stream or iterate CSV/XLSX; page-by-page PDF extraction.

## Error Handling
- Clear errors for size limit, unsupported type, and extraction failures.
- Graceful fallback to regex-only when spaCy missing.
- Partial detection allowed when some pages fail.

## Acceptance Criteria
- Detect and highlight listed PII types with <3% false positives on high-sensitivity IDs.
- Bank account + IFSC detection recalls expected patterns; avoids phone/card/Aadhaar collisions.
- Masking modes produce irreversible sanitization for Aadhaar/PAN/Passport/Cards/Bank accounts.
- 10 MB PDF/CSV complete in <5s locally.
- No outbound network during processing.
- spaCy absence does not crash; regex-only path works.
- CLI processes both inline text and file inputs; masking and JSON output flags functional.

## Risks & Mitigations
- False positives/negatives: checksums/context and IFSC validation; threshold tuning.
- PDF extraction variability: provide TXT fallback on download.
- Performance on large tables: stream rows, avoid full in-memory dataframes.
- Synthetic data trust: watermark synthetic replacements (SYN_PREFIX_n).

## Decisions
- Use best available offline spaCy model at runtime (prefer medium, fallback small); hybrid is default.
- Placeholder stripping is opt-in (flag-only by default).
- CLI available for offline/batch use alongside SPA web UI + REST API.
