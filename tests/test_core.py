import pandas as pd

from anomalydetector.core import detect_anomalies


def test_detect_anomalies_empty():
    res = detect_anomalies([])
    assert isinstance(res, pd.Series)
    assert res.dtype == bool
    assert res.empty


def test_detect_anomalies_simple():
    values = [1.0, 1.1, 0.9, 5.0]
    res = detect_anomalies(values, threshold=2.0)
    assert list(res) == [False, False, False, True]


def test_detect_anomalies_constant():
    values = [2.0, 2.0, 2.0]
    res = detect_anomalies(values)
    assert list(res) == [False, False, False]
