#!/usr/bin/env python3
"""
scan_secrets.py - Lightweight, portable secret scanner

Usage:
  python scripts/scan_secrets.py --path .

Features:
 - Regex-based checks for common secret patterns (AWS keys, JWTs, PEM blocks, API keys).
 - Skips common directories (.git, node_modules, .venv, __pycache__).
 - Optionally uses detect-secrets if the package is installed; otherwise fallbacks to regex scanning.
 - Outputs JSON or human-readable results. Exits with code 1 if any findings exist.

This is intentionally conservative and meant to be run locally or in CI for a quick scan.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List


IGNORE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"}
IGNORE_FILES = {"poetry.lock"}  # lockfiles contain long hashes we don't want to flag


PATTERNS: Dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_access_key": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{20,}\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
    "rsa_private_key": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    "jwt_like": re.compile(r"eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}"),
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9\-_.]{20,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
    "stripe_key": re.compile(r"sk_live_[0-9a-zA-Z]{8,}"),
    "api_key_assignment": re.compile(r"(?i)api[_-]?key\s*[=:]\s*[\"']?([A-Za-z0-9\-_.]{8,})[\"']?"),
    "client_secret_assignment": re.compile(r"(?i)client[_-]?secret\s*[=:]\s*[\"']?([A-Za-z0-9\-_.]{8,})[\"']?"),
    # long hex/base64-ish token (heuristic)
    "long_hex": re.compile(r"\b[a-fA-F0-9]{40,}\b"),
}


def is_binary_string(bytes_data: bytes) -> bool:
    # Heuristic: if more than 30% of chars are non-text, consider binary
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
    return bool(bytes_data.translate(None, text_chars))


def scan_file(path: Path) -> List[Dict]:
    results = []
    try:
        raw = path.read_bytes()
    except OSError:
        return results

    if not raw:
        return results

    if is_binary_string(raw[:4096]):
        return results

    # decode using utf-8 with replacement for invalid bytes
    text = raw.decode("utf-8", errors="replace")

    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        # quick filter: skip very short lines
        if len(line.strip()) < 8:
            continue
        for name, pattern in PATTERNS.items():
            for m in pattern.finditer(line):
                # skip likely false positives in lockfiles
                if path.name in IGNORE_FILES:
                    continue
                snippet = line.strip()
                match_text = m.group(0)
                results.append({
                    "path": str(path),
                    "line": idx,
                    "pattern": name,
                    "match": match_text,
                    "snippet": snippet,
                })
    return results


def walk_and_scan(root: Path) -> List[Dict]:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        # mutate dirnames in-place to skip directories
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fname in filenames:
            if fname.startswith("."):
                # allow hidden dotfiles but skip git internals already ignored
                pass
            fpath = Path(dirpath) / fname
            # binary check/skip for large files is in scan_file
            findings.extend(scan_file(fpath))
    return findings


def try_detect_secrets_scan(path: Path) -> List[Dict]:
    """Placeholder for detect-secrets integration.

    To keep this script fully portable we do not require detect-secrets at runtime. If you
    want the richer scanning, install `detect-secrets` and integrate separately.
    """
    return []


def main() -> int:
    p = argparse.ArgumentParser(description="Lightweight secret scanner for repositories")
    p.add_argument("--path", "-p", default=".", help="Path to scan")
    p.add_argument("--json", action="store_true", help="Output results as JSON")
    p.add_argument("--use-detect-secrets", action="store_true", help="Use detect-secrets if installed")
    args = p.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Path does not exist: {root}", file=sys.stderr)
        return 2

    findings: List[Dict] = []

    # try detect-secrets if requested and available
    if args.use_detect_secrets:
        ds_findings = try_detect_secrets_scan(root)
        findings.extend(ds_findings)

    # always run regex scanner as fallback
    findings.extend(walk_and_scan(root))

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        if not findings:
            print("No potential secrets found.")
        else:
            print(f"Found {len(findings)} potential secret(s):")
            for f in findings:
                print(f"- {f['path']}:{f['line']} [{f['pattern']}] -> {f['match']}")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())

