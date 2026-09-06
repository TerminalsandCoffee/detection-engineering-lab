# Development scripts

These commands validate and export the legacy TOML collection. TOML rules target Elastic-compatible query APIs; native Wazuh XML rules are tested separately. Schema and ATT&CK mapping checks do not prove that a detection fires on real telemetry.

Use Python 3.11 or newer and install `python -m pip install -r requirements.txt` in a virtual environment. Run the examples below from the repository root. Existing `cd development; python validation.py` style commands also work: default input and output paths are resolved from the repository, not the working directory.

## Validate locally

```bash
python development/validation.py
python -m unittest discover -s tests -v
```

The validator checks dates, rule types, required values, UUID uniqueness, score types, and every ATT&CK mapping's structure. Missing or empty input directories and invalid files return a nonzero exit code. All exporters validate their complete input before writing or sending results.

To check names, tactic membership, subtechnique relationships, and retired identifiers against the current official enterprise ATT&CK catalog:

```bash
python development/mitre.py
```

That command downloads the [official MITRE CTI catalog](https://github.com/mitre/cti/tree/master/enterprise-attack). For repeatable or offline validation, provide a previously downloaded enterprise STIX JSON snapshot:

```bash
python development/mitre.py --attack-data /path/to/enterprise-attack.json
```

Record the snapshot's source, revision, and hash with your results. The tiny catalog under `tests/fixtures/` is synthetic test data; it cannot validate this repository's full collection. Unit tests exercise mapping failures offline; the optional manual CI job checks the current online catalog.

## Export reports

| Command | Stable output |
|---|---|
| `python development/toml_to_csv.py` | `metrics/detectiondata.csv` |
| `python development/toml_to_navigator.py` | `metrics/navigator.json` |
| `python development/toml_to_report.py` | `metrics/latestdetections.md` |
| `python development/toml_to_md.py` | `metrics/recentdetections.md` |

Every command accepts `--detections-dir PATH`. Report commands also accept `--output-dir PATH`; explicitly supplied relative paths resolve from the current directory. The two monthly reports accept `--as-of YYYY-MM-DD`, group by original `creation_date`, and state when a month has no new rules. Their historical filenames remain available for existing links and scripts.

CSV fields use proper quoting. Navigator exports all technique/tactic combinations, with scores representing the number of rules mapped to each pair. Those counts do not establish validated detection coverage. The output uses the [Navigator 4.5 layer format](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md), without claiming a particular ATT&CK catalog version.

## Preview Elastic payloads

```bash
python development/toml_to_json.py --dry-run
```

Preview requires no API key or network access. The payload preserves fields in `[rule]`, including the lookback, thresholds, indices, and an explicit `enabled = false`. Local `[metadata]` is excluded. Historical query/threshold examples without a language default to `kuery`; an explicit `lucene` value is preserved. EQL requires `language = "eql"`. Unsupported types, invalid language values, and malformed rules fail validation.

For changed-rule previews, set `CHANGED_FILES` to exact repository paths separated by spaces or commas, or a JSON array of paths, then run:

```bash
python development/update_alert.py --dry-run
```

Unambiguous basenames remain supported for older callers. Missing or ambiguous TOML paths fail; deleting a file does not delete a remote rule. No changed TOML files means no operation.

## Optional Elastic upload

The non-preview commands write to the configured SIEM:

```bash
python development/toml_to_json.py
python development/update_alert.py
```

Both require `ELASTIC_KEY` and `ELASTIC_URL`. Set the URL to the full rules endpoint, for example `https://your-kibana.example/api/detection_engine/rules`, and keep credentials out of source files. These are legacy Elastic adapters, not Wazuh deployment tools. Review payloads and the [Elastic API contract](https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-createrule) for your target version before use; tests use HTTP fixtures and do not verify a live SIEM integration.

Updates use the payload's `rule_id`; only HTTP 404 triggers creation. Requests have a timeout, unsuccessful responses return a nonzero exit code, and failed requests are never reported as successful. Missing `enabled` retains the historical default of `true`; set it explicitly to keep a rule disabled. Multi-rule uploads are not transactional, so a later failure can leave earlier rules uploaded.

## CI and native Wazuh checks

Pushes to `main` and pull request CI run the Python tests with Terraform 1.16.1 available, validate the actual TOML collection, preview API payloads, and generate reports. Separate Linux jobs validate the canonical Terraform configuration without a backend or cloud credentials and run `bash tests/wazuh_logtest.sh`. The native harness uses an isolated pinned official Wazuh container; see [the fixture notes](../tests/fixtures/wazuh/README.md) for its scope.

The workflow at the historical `deploy-rules.yml` path now performs manual validation only. Elastic workflows produce previews, and the manual metrics workflow uploads report artifacts. No workflow applies Terraform, uploads rules to a SIEM, or force-pushes generated files. Online ATT&CK validation is an optional manual job.
