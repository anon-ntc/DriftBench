# DriftBench collection pipeline

This directory contains the complete collection and preprocessing pipeline:

- `driftbench_pipeline.py` implements collection, sessionization, annotation, deterministic selection, sanitization, and verification.
- `README.md` documents input, stage, and output contract.

## Requirements

- Python 3.10 or newer
- Linux with `renameat2` for atomic no-clobber publication
- Classic PCAP input with Ethernet link type for the reference sessionizer
- Hash-bound capture, browser, and driver executables for collection

## Command sequence

Run commands from this directory. Every mutating command requires a new output
path and refuses to replace an existing directory.

```bash
python3 driftbench_pipeline.py \
  --config campaign.json \
  collect \
  --schedule collection_schedule.csv \
  --output collection_v1

python3 driftbench_pipeline.py \
  --config campaign.json \
  sessionize \
  --input-manifest collection_v1/parent_capture_manifest.csv \
  --output sessions_v1

python3 driftbench_pipeline.py \
  --config campaign.json \
  annotate \
  --input-manifest sessions_v1/session_manifest.csv \
  --output annotations_v1

python3 driftbench_pipeline.py \
  --config campaign.json \
  select \
  --input-manifest annotations_v1/annotation_manifest.csv \
  --output splits_v1

python3 driftbench_pipeline.py \
  --config campaign.json \
  sanitize \
  --input-manifest splits_v1/split_manifest.csv \
  --output sanitized_v1

python3 driftbench_pipeline.py \
  --config campaign.json \
  verify \
  --input-manifest collection_v1/parent_capture_manifest.csv \
  --input-manifest sessions_v1/session_manifest.csv \
  --input-manifest annotations_v1/annotation_manifest.csv \
  --input-manifest splits_v1/split_manifest.csv \
  --input-manifest sanitized_v1/sanitized_manifest.csv \
  --output verification_v1
```

## Configuration files

Create the following three JSON files beside `campaign.json`. Paths in the campaign file are resolved relative to the campaign file.

### `campaign.json`

```json
{
  "schema_version": "driftbench-open-science-pipeline-v1",
  "campaign_id": "replace-with-sealed-campaign-id",
  "page_inventory": "page_inventory.json",
  "configuration_inventory": "configuration_inventory.json",
  "schedule": "collection_schedule.csv",
  "repetitions_per_page": 100,
  "collection": {
    "capture_command": [
      "{capture_binary}",
      "-i",
      "{capture_interface}",
      "-F",
      "pcap",
      "-w",
      "{capture_path}"
    ],
    "visit_command": [
      "driftbench-browser-visit",
      "--browser-binary",
      "{browser_binary}",
      "--driver-binary",
      "{driver_binary}",
      "--url",
      "{url}",
      "--fresh-private-profile"
    ],
    "capture_ready_seconds": 3.0,
    "post_visit_seconds": 3.0,
    "visit_timeout_seconds": 60.0,
    "capture_stop_timeout_seconds": 5.0,
    "environment": {},
    "retry_policy": {
      "max_attempts": 3,
      "backoff_seconds": 5.0,
      "retryable_reasons": [
        "capture_launch_failed",
        "capture_exited_before_visit",
        "visit_launch_failed",
        "visit_timeout",
        "visit_command_failed",
        "capture_missing_or_empty",
        "capture_stop_failed"
      ]
    }
  },
  "annotation": {
    "allowlist": [
      "class-a.invalid",
      "class-b.invalid"
    ],
    "minimum_session_bytes": 512,
    "require_scheduled_class_match": true
  },
  "selection": {
    "namespace": "replace-with-immutable-selection-namespace",
    "ratios": [70, 15, 15],
    "per_cell_limit": 300
  },
  "sanitization": {
    "max_packets": 50
  }
}
```

The allowlist may instead be an object that maps each exact SNI to a class
name. Selection ratios must be `[70, 15, 15]`. The cell limit may be `null`
or a positive integer.

### `page_inventory.json`

```json
{
  "schema_version": "driftbench-page-inventory-v1",
  "pages": [
    {
      "page_id": "class-a-index",
      "class_name": "class-a.invalid",
      "url": "https://class-a.invalid/",
      "page_role": "index",
      "replacement_for_page_id": null,
      "replacement_reason": null
    },
    {
      "page_id": "class-b-index",
      "class_name": "class-b.invalid",
      "url": "https://class-b.invalid/",
      "page_role": "index",
      "replacement_for_page_id": null,
      "replacement_reason": null
    }
  ]
}
```

`page_role` must be `index` or `subpage`. Replacement fields must either
both be null or both be populated. A replacement target must identify another
page in the same inventory.

### `configuration_inventory.json`

```json
{
  "schema_version": "driftbench-configuration-inventory-v1",
  "configurations": [
    {
      "configuration_id": "C26-U-CR-A",
      "campaign": "2026",
      "os": "ubuntu",
      "os_version": "22.04",
      "browser": "chromium",
      "browser_version": "REPLACE_WITH_EXACT_VERSION",
      "network": "network-a",
      "capture_interface": "REPLACE_WITH_INTERFACE",
      "capture_binary": "tshark",
      "capture_binary_version": "REPLACE_WITH_EXACT_VERSION",
      "capture_binary_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "browser_binary": "chromium",
      "browser_binary_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "driver_binary": "chromedriver",
      "driver_version": "REPLACE_WITH_EXACT_VERSION",
      "driver_binary_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
      "sessionizer_binary": "",
      "sessionizer_version": "",
      "sessionizer_binary_sha256": "",
      "sessionizer_compatibility": "",
      "environment_image_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
      "enabled": true
    }
  ]
}
```

Add one object per collection configuration. Capture, browser, and driver hashes are lowercase SHA-256 values. The four sessionizer fields must all be empty or all be populated. A populated compatibility value must be `splitcap-compatible`.

The examples use reserved `.invalid` hostnames, placeholder executable names, and non-authoritative hashes. Replace every placeholder with sealed campaign values before collection. Do not edit a sealed campaign configuration.

## Collection schedule contract

`collection_schedule.csv` is UTF-8 with a header and LF line endings. Its ordered header must be exactly:

```text
visit_id,parent_group_id,campaign,configuration_id,os,browser,network,class_name,page_id,url,repetition,os_version,environment_image_digest,capture_interface,capture_binary,capture_binary_version,capture_binary_sha256,browser_binary,browser_version,browser_binary_sha256,driver_binary,driver_version,driver_binary_sha256,sessionizer_binary,sessionizer_version,sessionizer_binary_sha256,sessionizer_compatibility
```

`visit_id` and `parent_group_id` must each be unique. The schedule must contain the exact page, enabled configuration, and repetition cross-product. Hash and seal the schedule and all three JSON inputs before the first visit.

## Published outputs

All CSV manifests repeat the relevant collection identity fields. The primary
stage outputs are:

| Stage | Manifest | Additional bindings |
| --- | --- | --- |
| collect | `collection_attempt_manifest.csv` | attempt lineage, status, retry state, logs, PCAP path and hash |
| collect | `parent_capture_manifest.csv` | terminal and selected attempts, status, PCAP path and hash |
| sessionize | `session_manifest.csv` | opaque session ID, ordinal, packet count, status, PCAP path and hash |
| annotate | `annotation_manifest.csv` | SNI, annotated class, status, rejection reason |
| select | `split_manifest.csv` | split version, leakage group, label ID, split, deterministic rank and key |
| sanitize | `sanitized_manifest.csv` | sanitizer versions, source hash, output path and hash |
| verify | `verification.json` | manifest hashes, row counts, verified PCAP counts, split checks |

Collection, sessionization, annotation, selection, and sanitization also emit stage reports. Collection retains per-attempt results and logs. Sessionization and selection emit summary CSV files.