"""Simple local inference Flask app for the anomaly-detector.

This file is intended as a minimal template that can be containerized for
Fargate/Lambda/SageMaker. It exposes a single /infer endpoint that accepts
JSON with a "values" key containing a list of numbers and returns a JSON
object with a boolean list `anomalies` with the same length.
"""
from typing import List

from flask import Flask, request, jsonify

from anomalydetector.core import detect_anomalies

app = Flask(__name__)


@app.route("/infer", methods=["POST"])
def infer():
    payload = request.get_json(force=True)
    values: List[float] = payload.get("values", [])
    series = detect_anomalies(values)
    return jsonify({"anomalies": list(map(bool, series.tolist()))})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
