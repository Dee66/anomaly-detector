from scripts.detector_inference import app


def test_inference_endpoint_smoke():
    client = app.test_client()
    payload = {"values": [1.0, 1.0, 1.0, 10.0]}
    resp = client.post("/infer", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "anomalies" in data
    assert isinstance(data["anomalies"], list)
    assert len(data["anomalies"]) == len(payload["values"])
