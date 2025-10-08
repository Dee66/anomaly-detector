from typing import Sequence

import numpy as np
import pandas as pd


def detect_anomalies(values: Sequence[float], threshold: float = 3.0) -> pd.Series:
    """Detect anomalies in a sequence of numbers.

    Uses a robust modified z-score based on the median and MAD (median absolute deviation).
    The modified z-score is defined as: 0.6745 * (x - median) / MAD. This is robust to
    extreme outliers. If the MAD is zero (no spread), the function falls back to a
    standard z-score using the mean and population standard deviation.

    Returns a boolean Pandas Series aligned with input values where True means anomaly.
    """
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        return pd.Series([], dtype=bool)

    # Robust approach: modified z-score using median and MAD
    median = np.median(arr)
    abs_dev = np.abs(arr - median)
    mad = np.median(abs_dev)

    if mad > 0:
        # 0.6745 is used to make the modified z-score comparable to the standard z-score
        modified_z = 0.6745 * (arr - median) / mad
        return pd.Series(np.abs(modified_z) > threshold)

    # Fallback: standard z-score
    mean = arr.mean()
    std = arr.std(ddof=0)
    if std == 0:
        return pd.Series([False] * arr.size)

    z = np.abs((arr - mean) / std)
    return pd.Series(z > threshold)
