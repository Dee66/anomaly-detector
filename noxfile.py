"""Noxfile for the anomaly detector project.

Provides automated sessions for:
- Linting and formatting
- Testing with coverage
- Type checking
- Security scanning
- Package building
"""

import nox

# Python versions to test against
PYTHON_VERSIONS = ["3.11"]

# Common locations
PACKAGE_DIR = "anomalydetector"
SRC_DIR = "src"
TESTS_DIR = "tests"


@nox.session(python=PYTHON_VERSIONS)
def tests(session):
    """Run the test suite with coverage."""
    session.install(".")
    session.install("pytest", "pytest-cov", "pytest-mock")

    session.run(
        "pytest",
        "--cov=" + PACKAGE_DIR,
        "--cov-report=term-missing",
        "--cov-report=html",
        "--cov-fail-under=80",
        *session.posargs,
    )


@nox.session(python=PYTHON_VERSIONS)
def lint(session):
    """Run linting with ruff."""
    session.install("ruff")
    session.run("ruff", "check", ".")


@nox.session(python=PYTHON_VERSIONS)
def format(session):
    """Format code with black and ruff."""
    session.install("black", "ruff")
    session.run("black", ".")
    session.run("ruff", "check", "--fix", ".")


@nox.session(python=PYTHON_VERSIONS)
def typecheck(session):
    """Run type checking with mypy."""
    session.install(".")
    session.install("mypy", "types-PyYAML")
    session.run("mypy", PACKAGE_DIR, SRC_DIR)


@nox.session(python=PYTHON_VERSIONS)
def security(session):
    """Run security checks."""
    session.install("bandit[toml]", "safety")
    session.run("bandit", "-r", PACKAGE_DIR, SRC_DIR)
    session.run("safety", "check")


@nox.session(python=PYTHON_VERSIONS)
def package(session):
    """Build the package."""
    session.install("build")
    session.run("python", "-m", "build")


@nox.session(python=PYTHON_VERSIONS)
def e2e_security(session):
    """End-to-end security validation."""
    # Install the package and its dependencies
    session.install(".")
    session.install("bandit[toml]", "safety", "semgrep")

    # Run comprehensive security checks
    session.log("Running bandit security analysis...")
    session.run(
        "bandit", "-r", PACKAGE_DIR, SRC_DIR, "--format", "json", "-o", "bandit-report.json"
    )

    session.log("Running safety dependency check...")
    session.run("safety", "check", "--json", "--output", "safety-report.json")

    # Note: semgrep requires configuration, so we'll add it later
    session.log("Security validation complete. Check bandit-report.json and safety-report.json")


@nox.session(python=PYTHON_VERSIONS)
def docs(session):
    """Build documentation (placeholder)."""
    session.log("Documentation building not yet implemented")
    # TODO: Add sphinx or mkdocs setup


@nox.session
def clean(session):
    """Clean up build artifacts and cache files."""
    import shutil
    from pathlib import Path

    # Directories to clean
    clean_dirs = [
        ".pytest_cache",
        ".coverage",
        "htmlcov",
        "dist",
        "build",
        "*.egg-info",
        ".mypy_cache",
        ".ruff_cache",
        "__pycache__",
    ]

    for pattern in clean_dirs:
        for path in Path(".").glob(f"**/{pattern}"):
            if path.is_dir():
                session.log(f"Removing directory: {path}")
                shutil.rmtree(path)
            elif path.is_file():
                session.log(f"Removing file: {path}")
                path.unlink()


# Default session when running `nox` without arguments
nox.options.sessions = ["tests", "lint", "typecheck"]
