from __future__ import annotations

import io
from typing import List, Optional

from flask import Flask, jsonify, render_template, request

from pii_detector.config import DEFAULT_MAX_FILE_SIZE_BYTES
from pii_detector.detection import Entity, detect_pii, risk_score
from pii_detector.extract import SUPPORTED_TYPES, extract_text
from pii_detector.masking import apply_masks

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = DEFAULT_MAX_FILE_SIZE_BYTES


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/detect")
def api_detect():
    payload = _parse_payload()
    if payload.error:
        return jsonify({"error": payload.error}), 400

    entities = detect_pii(payload.text, mode=payload.mode)
    return jsonify(
        {
            "entities": [e.to_dict() for e in entities],
            "risk": risk_score(entities),
            "mode": payload.mode,
            "nlp": payload.mode != "regex",
            "text": payload.text,
        }
    )


@app.post("/api/mask")
def api_mask():
    payload = _parse_payload()
    if payload.error:
        return jsonify({"error": payload.error}), 400

    masking_mode = request.form.get("masking") or request.json.get("masking") if request.is_json else request.form.get("masking")
    if masking_mode not in {"partial", "full", "synthetic"}:
        masking_mode = "full"

    include_placeholders = False
    if request.is_json:
        include_placeholders = bool(request.json.get("includePlaceholders", False))
        allowed_labels = request.json.get("maskTypes") or []
    else:
        include_placeholders = request.form.get("includePlaceholders") == "true"
        allowed_labels = request.form.getlist("maskTypes") if request.form else []

    if allowed_labels:
        # accept comma-separated string fallback
        if isinstance(allowed_labels, str):
            allowed_labels = [lbl.strip() for lbl in allowed_labels.split(",") if lbl.strip()]
    else:
        allowed_labels = []

    entities = detect_pii(payload.text, mode=payload.mode)
    masked = apply_masks(
        payload.text,
        entities,
        mode=masking_mode,
        include_placeholders=include_placeholders,
        allowed_labels=allowed_labels or None,
    )
    return jsonify(
        {
            "masked": masked,
            "masking": masking_mode,
            "includePlaceholders": include_placeholders,
            "maskTypes": allowed_labels,
        }
    )


class Payload:
    def __init__(self, text: str = "", mode: str = "hybrid", error: Optional[str] = None):
        self.text = text
        self.mode = mode
        self.error = error


def _parse_payload() -> Payload:
    mode = "hybrid"
    if request.is_json and request.json:
        mode = request.json.get("mode", "hybrid")
        text = request.json.get("text") or ""
        if not text:
            return Payload(error="text is required for JSON requests")
        return Payload(text=text, mode=mode)

    uploaded = request.files.get("file")
    text = request.form.get("text") or ""
    if uploaded:
        filename = uploaded.filename or ""
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        if ext not in SUPPORTED_TYPES:
            return Payload(error="unsupported file type")
        data = uploaded.read()
        if len(data) > DEFAULT_MAX_FILE_SIZE_BYTES:
            return Payload(error="file too large")
        try:
            text = extract_text(filename, data)
        except Exception as exc:  # pragma: no cover - extraction errors
            return Payload(error=f"failed to parse file: {exc}")
    if not text:
        return Payload(error="text or file is required")

    mode = request.form.get("mode", mode)
    if mode not in {"regex", "hybrid"}:
        mode = "hybrid"
    return Payload(text=text, mode=mode)


if __name__ == "__main__":
    app.run(debug=True)
