### Multi-stage Dockerfile for anomaly-detector inference service
### Stage 1: builder (uses Poetry to install dependencies)
FROM python:3.11-slim as builder

ENV POETRY_HOME=/opt/poetry
ENV POETRY_NO_INTERACTION=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry (lightweight installer)
RUN curl -sSL https://install.python-poetry.org | python - --version 1.9.6
ENV PATH="$POETRY_HOME/bin:$PATH"

WORKDIR /src

# Copy dependency manifests only for layer caching
COPY pyproject.toml poetry.lock* /src/

# Install only production dependencies into the builder venv
RUN poetry config virtualenvs.create false && poetry install --no-interaction --no-ansi --no-dev

### Stage 2: runtime
FROM python:3.11-slim

# Create a non-root user
RUN addgroup --system app && adduser --system --ingroup app app

WORKDIR /app

# Copy from the builder
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Copy application code (only what's needed)
COPY anomalydetector /app/anomalydetector
COPY src /app/src
COPY scripts/detector_inference.py /app/scripts/detector_inference.py

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

USER app

EXPOSE 8080

CMD ["python", "scripts/detector_inference.py"]
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml poetry.lock* /app/
RUN pip install --upgrade pip && pip install flask pandas numpy

COPY . /app

EXPOSE 8080

CMD ["python", "scripts/detector_inference.py"]
