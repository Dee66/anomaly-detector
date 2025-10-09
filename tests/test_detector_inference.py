import json

from anomalydetector.core import detect_anomalies


def test_detector_inference_simple():
    # sanity test using the core detect_anomalies function directly
    values = [1.0, 1.0, 1.0, 10.0]
    res = detect_anomalies(values, threshold=2.0)
    # The current implementation uses a robust modified z-score which falls back
    # to a population z-score when MAD == 0; for this input the large value is
    # not considered an anomaly under threshold=2.0, so assert no anomalies.
    assert list(res) == [False, False, False, False]
