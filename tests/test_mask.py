from app import app


def test_mask_returns_masked_text():
    client = app.test_client()
    payload = {"text": "Email: test@example.com", "mode": "regex", "masking": "full"}
    resp = client.post("/api/mask", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "[EMAIL]" in data["masked"]
