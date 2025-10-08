from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from .core import detect_anomalies


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="anomaly-detector")
    parser.add_argument("csv", help="Path to a CSV file with a single numeric column")
    parser.add_argument("--threshold", type=float, default=3.0, help="Z-score threshold")
    args = parser.parse_args(argv)

    path = Path(args.csv)
    if not path.exists():
        print(f"File not found: {path}")
        return 2

    df = pd.read_csv(path, header=None)
    if df.shape[1] > 1:
        print("CSV must contain a single numeric column")
        return 3

    series = df.iloc[:, 0]
    anomalies = detect_anomalies(series, threshold=args.threshold)
    out = pd.DataFrame({"value": series, "anomaly": anomalies})
    print(out.to_csv(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
