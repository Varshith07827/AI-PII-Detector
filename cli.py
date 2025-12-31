import argparse
import json
import os
import sys
from pii_detector.detection import detect_pii, risk_score
from pii_detector.masking import apply_masks

def main():
    parser = argparse.ArgumentParser(description="PII Detector CLI")
    parser.add_argument("input", help="Input text or path to a file")
    parser.add_argument("--output", "-o", help="Output file for masked text")
    parser.add_argument("--json", "-j", help="Output file for JSON report")
    parser.add_argument("--mode", choices=["regex", "hybrid"], default="hybrid", help="Detection mode (default: hybrid)")
    parser.add_argument("--mask-mode", choices=["full", "partial", "synthetic"], default="full", help="Masking mode (default: full)")
    
    args = parser.parse_args()
    
    text = args.input
    # Check if input is a file
    if os.path.exists(args.input):
        if os.path.isfile(args.input):
            try:
                with open(args.input, "r", encoding="utf-8") as f:
                    text = f.read()
            except Exception as e:
                print(f"Error reading file: {e}", file=sys.stderr)
                sys.exit(1)
        else:
             # It exists but is not a file (e.g. directory), treat as text? 
             # Or maybe user meant a file that doesn't exist?
             # If it's a directory, we probably shouldn't process it.
             print(f"Error: '{args.input}' is a directory.", file=sys.stderr)
             sys.exit(1)
    
    # If it doesn't exist as a file, we treat the string itself as input.
            
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
