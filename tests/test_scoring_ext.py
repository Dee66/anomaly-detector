import pandas as pd
import numpy as np

from anomalydetector.core import detect_anomalies


def test_detect_anomalies_empty():
    res = detect_anomalies([])
    assert isinstance(res, pd.Series)
    assert res.empty


def test_detect_anomalies_constant_series():
    vals = [5.0] * 10
    res = detect_anomalies(vals)
    assert not res.any()


def test_detect_anomalies_single_outlier():
    vals = [10, 10, 10, 10, 1000]
    res = detect_anomalies(vals, threshold=1.9)
    # last element should be True
    assert res.iloc[-1]
    assert res.iloc[:-1].sum() == 0
