# Detections

This collection contains **ten Elastic/KQL detections** in TOML and **one native Wazuh XML implementation**. TOML is the source format for metadata and query exports; Wazuh reads the XML in `wazuh-rules/`.

## Structure

- `*.toml`: Elastic-style rule definitions, identifiers, author credits, and ATT&CK mappings
- `wazuh-rules/`: native Wazuh rules
- `decoders/`: decoder examples; Windows eventchannel data uses Wazuh's built-in decoder
- `../tests/fixtures/wazuh/`: synthetic events for the native Wazuh example

## Current Detections

The severity below reflects each TOML file. Wazuh's numeric rule level is a separate scale.

| Detection | Severity | ATT&CK mapping | Required telemetry |
|---|---|---|---|
| [BAT files over HTTP on an unusual port](bat_files_observed_in_http_on_unusual_port.toml) | Medium | T1059.003 · Execution | Zeek HTTP normalized to ECS: dataset, URL extension, destination port |
| [Data archive for potential exfiltration](data_archive_for_exfil.toml) | Medium | T1074.001 · Collection | Elastic Endpoint file events: action, process, path, filename |
| [ZIP transfer over FTP](data_exfil_over_ftp.toml) | High | T1048.003 · Exfiltration | Zeek FTP: STOR action and command argument |
| [Excessive web traffic](excessive_web_traffic.toml) | Low | T1046 · Discovery | Zeek HTTP events and source IP; threshold rule engine |
| [Potential MSF PowerShell payload](msfvenom_powershell_payload.toml) | High | T1059.001 · Execution | Process command line and original message with the expected normalization |
| [PowerShell execution via BAT](powershell_exec_via_bat.toml) | Medium | T1059.001 · Execution | Process and parent command lines/name; Sysmon Event ID 1 for the [Wazuh version](wazuh-rules/powershell_exec_via_bat.xml) |
| [PowerShell downloading BAT files](powershell_invokewebrequest_downloading_bat.toml) | Medium | T1059.001 · Execution | Process command-line collection |
| [Script added to registry autorun](suspicious_file_added_to_registry.toml) | High | T1547.001 · Persistence | Normalized Windows Sysmon registry events, including path and value |
| [Suspicious file written to temp](suspicious_file_written_to_tmp.toml) | High | T1082 / T1217 · Discovery | Elastic Endpoint file events: action, process, path, filename |
| [Nmap/Nikto web-scanner user agent](web_scanner_activity_nmap_nikto.toml) | Low | T1046 · Discovery | Zeek HTTP dataset and user-agent field |

The [AWS lab](../setup/README.md) supplies Windows/Sysmon collection through Wazuh. It does not install Zeek, Elastic Endpoint, or an Elastic Security cluster. A native Sysmon event does not automatically contain the ECS fields used by the TOML queries.

## Query assumptions and limits

The query examples use [Kibana Query Language](https://www.elastic.co/docs/reference/query-languages/kql), including leading wildcards. Their behavior depends on field types, normalization, case, and the engine's wildcard settings. Check field mappings and inspect actual events before enabling a rule. Exports and schema validation do not execute these queries against Elasticsearch.

| Signal | Useful benign comparison or limitation |
|---|---|
| BAT download or PowerShell child of `cmd.exe` | Software deployment and support scripts can match; compare publisher, parent chain, user, and purpose. |
| ZIP in a temporary directory | Installers and support bundles create archives. File creation alone does not establish collection or theft. |
| FTP STOR of a ZIP | Approved transfers can match, and a command need not complete successfully. The mapping is a hypothesis about non-C2 transfer, not evidence of automation. |
| High HTTP event count | Monitoring, shared proxies, and load tests can exceed the threshold. The rule groups by source IP across destinations. |
| MSF command-line substring | A recognizable default pattern is narrow; changed flags or encoding can evade it, and literal sample text may match. |
| Registry value containing a script | Legitimate logon automation can match; inspect the complete key/value and execution context. |
| `History` or `.txt` file in a temp path | The pattern does not prove system/browser discovery. Correlate preceding process activity and file contents when available. |
| Nmap/Nikto user agent | Approved scans and spoofed strings can match; this does not detect all scanners. |

The Nmap/Nikto query groups both user-agent alternatives under the Zeek dataset condition. The FTP mapping describes the observed transfer protocol instead of inferring automated exfiltration. Original rule IDs and author metadata remain unchanged.

## Native Wazuh example

[PowerShell execution via BAT](wazuh-rules/powershell_exec_via_bat.xml) extends the Wazuh Sysmon process-creation rule and inspects the executable, parent executable, and parent command line. The example's custom rule ID is `100001`; check for a collision with existing local rules before installing it.

1. Run `bash tests/wazuh_logtest.sh` from the repository root on a host with Bash and Docker. The [fixture guide](../tests/fixtures/wazuh/README.md) documents the positive/negative cases and the temporary JSON adapter used only in that disposable container.
2. Confirm the Windows agent collects `Microsoft-Windows-Sysmon/Operational` using the [setup guide](../setup/README.md).
3. Copy the XML into the manager's `/var/ossec/etc/rules/` directory, preserving other local rules.
4. Run `sudo /var/ossec/bin/wazuh-analysisd -t` on the manager to check the installed configuration. Restart the manager only after that succeeds.
5. Generate a benign BAT-to-PowerShell action on the lab endpoint and confirm the resulting alert has rule ID `100001`, Sysmon Event ID `1`, and the expected command-line marker.

The container's raw JSON fixtures need a test-only decoder adapter. Do not modify production base rules to accept them. Native fixture tests exercise Wazuh's rule logic; actual Windows event collection and transport require the endpoint check.

See [Wazuh's custom-rule guidance](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html) and [rule-testing documentation](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html). Local regression tests and engine fixture tests are not proof of endpoint-to-alert delivery in your environment.

## Adding New Detections

1. Copy an existing TOML rule and assign a new UUID. Preserve attribution when adapting someone else's detection.
2. Record the data source, field mappings, detection hypothesis, and expected benign matches.
3. Run `python development/validation.py` and `python development/mitre.py` from the repository root.
4. Test the query or native rule in its actual engine against positive, negative, and edge cases.
5. Retain the evidence: engine/version, sanitized event, expected result, observed result, and tuning decision.
6. Regenerate the [metrics](../metrics/README.md) when metadata changes.

For a reusable evidence outline, see the [testing phase](../theory/detection-engineering-workflow.md#4-testing).
