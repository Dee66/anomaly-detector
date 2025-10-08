"""Deployment safety guard utilities.

This module provides strict checks to prevent accidental AWS operations.

To allow real deployments/uploads you must set BOTH environment variables:
- ALLOW_AWS_DEPLOY=1
- DEPLOY_CONFIRM=I_ACCEPT_COSTS

This double-confirmation reduces the risk of accidental costly actions.
"""
import os
import sys
from typing import Tuple


def _env_flag_true(val: str | None) -> bool:
    return (val or "").lower() in ("1", "true", "yes")


def is_deploy_allowed() -> bool:
    """Return True only if both confirmations are present.

    - ALLOW_AWS_DEPLOY must be set to a truthy value (1/true/yes)
    - DEPLOY_CONFIRM must exactly equal the acknowledgement string
    """
    allow = _env_flag_true(os.getenv("ALLOW_AWS_DEPLOY"))
    confirm = os.getenv("DEPLOY_CONFIRM", "") == "I_ACCEPT_COSTS"
    return allow and confirm


def require_deploy_allowed_or_exit(message: str | None = None) -> None:
    """Exit the process if deployment confirmations are not present.

    This should be called by any script that could perform real AWS operations
    (CDK deploy, S3 uploads, SageMaker training, etc.) when the operation is
    requested (for example when --apply is passed).
    """
    if is_deploy_allowed():
        return

    sys.stderr.write("ERROR: Real AWS deployments are disabled by default.\n")
    sys.stderr.write("To enable deployments, set BOTH environment variables:\n")
    sys.stderr.write("  ALLOW_AWS_DEPLOY=1\n")
    sys.stderr.write("  DEPLOY_CONFIRM=I_ACCEPT_COSTS\n")
    if message:
        sys.stderr.write(f"{message}\n")
    sys.exit(2)
