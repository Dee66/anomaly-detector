import sys
from pathlib import Path

# Add the anomaly-detector package directory to sys.path so tests can import it directly.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
