import sys
from pathlib import Path

# Add the anomaly-detector package directory to sys.path so tests can import it directly.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# Also add src/ to the path so tests can import modules as top-level packages like `detector`.
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# Note: tests expect real boto3 installed in the test environment. The project
# defines boto3 in pyproject.toml; prefer to install dependencies via Poetry
# rather than maintaining a local stub here.
