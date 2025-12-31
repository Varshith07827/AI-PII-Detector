import argparse
import json
import os
import sys
from pii_detector.config import DEFAULT_MAX_FILE_SIZE_BYTES
from pii_detector.detection import detect_pii, risk_score
from pii_detector.extract import SUPPORTED_TYPES, extract_text
from pii_detector.masking import apply_masks


def _load_text(input_value: str) -> str:
    if os.path.exists(input_value):
        if not os.path.isfile(input_value):
            print(f"Error: '{input_value}' is not a file.", file=sys.stderr)
            sys.exit(1)

        ext = input_value.lower().rsplit(".", 1)[-1] if "." in input_value else ""
        if ext not in SUPPORTED_TYPES:
            print(
                "Error: unsupported file type. Supported: "
                + ", ".join(sorted(SUPPORTED_TYPES)),
                file=sys.stderr,
            )
            sys.exit(1)

        if os.path.getsize(input_value) > DEFAULT_MAX_FILE_SIZE_BYTES:
            print("Error: file too large (limit 10 MB).", file=sys.stderr)
            sys.exit(1)

        try:
            with open(input_value, "rb") as f:
                data = f.read()
            return extract_text(os.path.basename(input_value), data)
        except Exception as e:
            print(f"Error reading/parsing file: {e}", file=sys.stderr)
            sys.exit(1)

    return input_value

def main():
    parser = argparse.ArgumentParser(description="PII Detector CLI")
    parser.add_argument("input", help="Input text or path to a file")
    parser.add_argument("--output", "-o", help="Output file for masked text")
    parser.add_argument("--json", "-j", help="Output file for JSON report")
    parser.add_argument("--mode", choices=["regex", "hybrid"], default="hybrid", help="Detection mode (default: hybrid)")
    parser.add_argument("--mask-mode", choices=["full", "partial", "synthetic"], default="full", help="Masking mode (default: full)")
    
    args = parser.parse_args()
    
    text = _load_text(args.input)

    print(f"Processing input ({len(text)} chars)...", file=sys.stderr)
    
    entities = detect_pii(text, mode=args.mode)
    masked_text = apply_masks(text, entities, mode=args.mask_mode)
    risk = risk_score(entities)
    
    # Prepare report
    report = {
        "risk_score": risk,
        "entities": [e.to_dict() for e in entities],
        "masked_text": masked_text
    }
    
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(masked_text)
            print(f"Masked text written to {args.output}", file=sys.stderr)
        except Exception as e:
            print(f"Error writing output file: {e}", file=sys.stderr)
            
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"JSON report written to {args.json}", file=sys.stderr)
        except Exception as e:
            print(f"Error writing JSON report: {e}", file=sys.stderr)
            
    if not args.output and not args.json:
        print("--- Masked Text ---")
        print(masked_text)
        print("\n--- Risk Report ---")
        print(json.dumps(risk, indent=2))

if __name__ == "__main__":
    main()
