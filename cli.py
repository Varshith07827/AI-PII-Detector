import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Tuple
from pii_detector.config import DEFAULT_MAX_FILE_SIZE_BYTES
from pii_detector.detection import Entity, detect_pii, risk_score
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


def _collect_files(input_path: str) -> List[str]:
    """Collect all supported files from a path (file or directory)."""
    path = Path(input_path)
    
    if path.is_file():
        ext = path.suffix.lstrip('.').lower()
        if ext in SUPPORTED_TYPES:
            return [str(path)]
        return []
    
    if path.is_dir():
        files = []
        for ext in SUPPORTED_TYPES:
            files.extend(path.rglob(f"*.{ext}"))
        return [str(f) for f in files if f.is_file() and f.stat().st_size <= DEFAULT_MAX_FILE_SIZE_BYTES]
    
    return []


def _filter_entities(entities: List[Entity], min_confidence: float) -> List[Entity]:
    """Filter entities by minimum confidence threshold."""
    return [e for e in entities if e.confidence >= min_confidence]


def _process_single(file_path: str, mode: str, min_confidence: float) -> Tuple[str, List[Entity], dict]:
    """Process a single file and return text, filtered entities, and risk."""
    text = _load_text(file_path)
    entities = detect_pii(text, mode=mode)
    filtered = _filter_entities(entities, min_confidence)
    risk = risk_score(filtered)
    return text, filtered, risk


def main():
    parser = argparse.ArgumentParser(description="PII Detector CLI")
    parser.add_argument("input", help="Input text, file path, or directory path")
    parser.add_argument("--output", "-o", help="Output file for masked text (single file mode only)")
    parser.add_argument("--json", "-j", help="Output file for JSON report")
    parser.add_argument("--mode", choices=["regex", "hybrid"], default="hybrid", help="Detection mode (default: hybrid)")
    parser.add_argument("--mask-mode", choices=["full", "partial", "synthetic"], default="full", help="Masking mode (default: full)")
    parser.add_argument("--min-confidence", type=float, default=0.0, help="Minimum confidence threshold (0.0-1.0, default: 0.0)")
    parser.add_argument("--batch", action="store_true", help="Process directory recursively")
    
    args = parser.parse_args()
    
    # Validate confidence threshold
    if not 0.0 <= args.min_confidence <= 1.0:
        print("Error: --min-confidence must be between 0.0 and 1.0", file=sys.stderr)
        sys.exit(1)
    
    # Batch mode: process directory
    if args.batch or (os.path.exists(args.input) and os.path.isdir(args.input)):
        files = _collect_files(args.input)
        if not files:
            print(f"No supported files found in '{args.input}'", file=sys.stderr)
            sys.exit(1)
        
        print(f"Processing {len(files)} file(s)...", file=sys.stderr)
        
        batch_results = []
        total_entities = 0
        combined_risk = {"score": 0, "bucket": "low", "counts": {}, "placeholders": 0}
        
        for file_path in files:
            try:
                text, entities, risk = _process_single(file_path, args.mode, args.min_confidence)
                masked_text = apply_masks(text, entities, mode=args.mask_mode)
                
                batch_results.append({
                    "file": file_path,
                    "entities": [e.to_dict() for e in entities],
                    "risk": risk,
                    "masked_text": masked_text
                })
                
                total_entities += len(entities)
                combined_risk["score"] = max(combined_risk["score"], risk["score"])
                for label, count in risk["counts"].items():
                    combined_risk["counts"][label] = combined_risk["counts"].get(label, 0) + count
                combined_risk["placeholders"] += risk["placeholders"]
                
                print(f"  {file_path}: {len(entities)} entities, risk={risk['bucket']}", file=sys.stderr)
            except Exception as e:
                print(f"  {file_path}: ERROR - {e}", file=sys.stderr)
        
        # Update combined risk bucket
        score = combined_risk["score"]
        combined_risk["bucket"] = "critical" if score >= 80 else "high" if score >= 50 else "medium" if score >= 20 else "low"
        
        # Output batch report
        batch_report = {
            "summary": {
                "files_processed": len(batch_results),
                "total_entities": total_entities,
                "combined_risk": combined_risk,
                "min_confidence": args.min_confidence
            },
            "results": batch_results
        }
        
        if args.json:
            try:
                with open(args.json, "w", encoding="utf-8") as f:
                    json.dump(batch_report, f, indent=2)
                print(f"\nBatch report written to {args.json}", file=sys.stderr)
            except Exception as e:
                print(f"Error writing batch report: {e}", file=sys.stderr)
        else:
            print("\n--- Batch Summary ---")
            print(json.dumps(batch_report["summary"], indent=2))
        
        return
    
    # Single file/text mode
    text = _load_text(args.input)

    print(f"Processing input ({len(text)} chars)...", file=sys.stderr)
    
    entities = detect_pii(text, mode=args.mode)
    filtered_entities = _filter_entities(entities, args.min_confidence)
    
    if args.min_confidence > 0.0:
        print(f"Filtered {len(entities) - len(filtered_entities)} entities below confidence {args.min_confidence}", file=sys.stderr)
    
    masked_text = apply_masks(text, filtered_entities, mode=args.mask_mode)
    risk = risk_score(filtered_entities)
    
    # Prepare report
    report = {
        "risk_score": risk,
        "entities": [e.to_dict() for e in filtered_entities],
        "masked_text": masked_text,
        "min_confidence": args.min_confidence
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
