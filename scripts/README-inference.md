# Inference container: build & run

This describes how to build and run the production-ready inference container for the anomaly-detector.

Build (local):

```bash
# From repository root
docker build -f scripts/Dockerfile -t anomaly-detector-inference:latest .
```

Run (local):

```bash
# Expose port 8080 and run
docker run --rm -p 8080:8080 anomaly-detector-inference:latest
```

Invoke (example):

```bash
curl -s -X POST http://localhost:8080/infer -H 'Content-Type: application/json' \
  -d '{"values": [1,1,1,10]}' | jq
```

Notes:
- The Dockerfile uses Poetry in the build stage to install runtime dependencies only (no dev deps).
- For production images consider scanning the image (`trivy`/`grype`) and pinning base image digests.
- For deployment to ECR / Fargate, build and push to your registry and use a task definition referencing the image.
