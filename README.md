# PII Detector – AI Privacy Protection Tool

Offline-first Flask app that detects, scores, highlights, and masks PII in pasted text or uploaded files (PDF, DOCX, CSV, XLSX, TXT). Hybrid regex + optional spaCy mode, plus a CLI for offline/batch use.

## Quick start

1. Create/activate a virtualenv (already configured at `.venv` if you used the setup tools).
2. Install base deps:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Install NLP extras for spaCy:
   ```bash
   pip install -r requirements-nlp.txt
   python -m spacy download en_core_web_md || python -m spacy download en_core_web_sm
   ```
4. Run the app:
   ```bash
   flask --app app run --reload
   ```
5. Open http://127.0.0.1:5000 and test.

## CLI Usage

You can use the CLI tool to process text or files directly from the command line.

```bash
# Process text string
python cli.py "My email is test@example.com"

# Process a file
python cli.py path/to/document.txt

# Save masked output to a file
python cli.py input.txt --output masked.txt

# Generate JSON report
python cli.py input.txt --json report.json

# Specify detection and masking modes
python cli.py input.txt --mode regex --mask-mode partial
```

## Features

- Multi-format ingest with in-memory parsing; 10 MB max; no data stored.
- Regex detection for Aadhaar, PAN, Passport (IN), credit/debit cards (Luhn), phone/email/IP/DOB, bank accounts with IFSC cues, placeholder/fake data.
- Optional spaCy hybrid mode for names, addresses, dates; falls back to regex-only if unavailable.
- Risk scoring with compliance hints (GDPR/DPDP/HIPAA), heat-map highlighting, and masking modes (partial, full, synthetic). Placeholders can be flagged or masked (opt-in).
- Masking can target a single detected type (e.g., only emails) or all types.
- Offline-only: no external API calls.
- CLI supports text or file inputs, detection/masking mode selection, and JSON reporting.

## API (draft)

- `POST /api/detect` (multipart or JSON): `text` or `file`, `mode` (`regex|hybrid`). Returns entities and risk.
- `POST /api/mask` (JSON or form): `text`, `mode`, `masking` (`partial|full|synthetic`), `includePlaceholders` (bool). Returns masked text.
- `GET /health`: liveness.

## Tests

```bash
pytest
```

## Notes

- Placeholder stripping/replacement is opt-in; defaults to flagging only.
- For best NLP accuracy, prefer `en_core_web_md` if available; auto-fallback to small model.
- Python 3.12 virtualenv provided at `.venv312` (recommended for spaCy compatibility); base `.venv` is 3.13.
