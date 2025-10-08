S3 transfer tuning for model packaging

The packaging script (`scripts/package_model_artifacts.py`) supports optional S3 transfer tuning via the project configuration under `s3.transfer`.

Config options (place under `s3` in your environment YAML):

- multipart_threshold: int (bytes)
  - Files with size >= this value will use a boto3 `TransferConfig` to enable multipart uploads.
  - Default: 8 MiB (8388608 bytes)

- transfer_config_kwargs: mapping
  - Forwarded to `boto3.s3.transfer.TransferConfig` when a multipart upload path is used.
  - Common options:
    - max_concurrency: int (default: 10 in production recommended)
    - multipart_chunksize: int (bytes) — size of each part

Example (YAML):

s3:
  transfer:
    multipart_threshold: 16777216  # 16 MiB
    transfer_config_kwargs:
      max_concurrency: 8
      multipart_chunksize: 8388608  # 8 MiB

Notes and recommendations
- For production uploads of large model artifacts (tens or hundreds of MB), increase `max_concurrency` and tune `multipart_chunksize` to trade memory/CPU vs throughput.
- The packaging script will only construct an adapter with these options when `s3_adapter` is not injected (tests typically inject a test adapter). For most CI/deploy usage the adapter is constructed from the config automatically.
- If you prefer to manage uploads externally, you can still provide a custom adapter implementation to `upload_to_s3()` during tests or automation.
