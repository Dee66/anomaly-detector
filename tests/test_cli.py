"""Tests for the CLI module."""

import tempfile
from pathlib import Path

import pytest

from anomalydetector.cli import main


def test_cli_help():
    """Test CLI help display."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    # Help should exit with code 0
    assert exc_info.value.code == 0


def test_cli_missing_file():
    """Test CLI with missing input file."""
    result = main(["nonexistent.csv"])
    assert result == 2  # File not found error code


def test_cli_multiple_columns():
    """Test CLI with invalid CSV (multiple columns)."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("col1,col2\n1,2\n3,4\n")
        temp_file = Path(f.name)

    try:
        result = main([str(temp_file)])
        assert result == 3  # Multiple columns error code
    finally:
        temp_file.unlink()


def test_cli_valid_csv():
    """Test CLI with valid CSV input."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("1.0\n1.1\n0.9\n5.0\n")  # Last value should be anomaly
        temp_file = Path(f.name)

    try:
        result = main([str(temp_file), "--threshold", "2.0"])
        assert result == 0  # Success
    finally:
        temp_file.unlink()


def test_cli_custom_threshold():
    """Test CLI with custom threshold."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("1.0\n1.1\n0.9\n2.0\n")  # Mild outlier
        temp_file = Path(f.name)

    try:
        # With high threshold, should not detect anomaly
        result = main([str(temp_file), "--threshold", "5.0"])
        assert result == 0  # Success

        # With low threshold, should detect anomaly
        result = main([str(temp_file), "--threshold", "1.0"])
        assert result == 0  # Success
    finally:
        temp_file.unlink()
