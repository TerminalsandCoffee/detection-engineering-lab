# Wazuh synthetic fixtures

`sysmon_cases.json` contains invented Windows Sysmon events. They contain no real
users, host data, payloads, or commands to execute. A positive case means the
analytic should match the stated process relationship; it does not label the
benign health-check example as malicious.

The cases cover batch paths with spaces, mixed case, quotes, command separators,
executable basename lookalikes, longer extensions, `.bat` directory names,
missing fields, and non-process events. The rule is a command-line heuristic:
an argument that merely mentions a `.bat` filename can still match. It cannot
prove the batch file caused the child process or parse all `cmd.exe` syntax.

Run from the repository root:

```bash
python -m unittest discover -s tests -p test_wazuh_rules.py -v
bash tests/wazuh_logtest.sh
```

The Python-only checks validate the XML contract and a regex subset shared with
Python. They explicitly skip the two native tests unless `WAZUH_LOGTEST` is set;
they do not prove Wazuh rule routing or PCRE2 behavior.

The shell harness uses the official `wazuh/wazuh-manager:4.14.7` image, pinned by
its manifest digest. Docker may download the image first. Fixture replay then
runs in a disposable container with networking disabled, no published ports,
and a read-only repository mount. Only the local analysis engine and database
start; no endpoint commands or remote deployment run.

**Test-only JSON adapter:** Wazuh's native Windows event-channel decoder is not
the generic JSON decoder used by `wazuh-logtest`. Following Wazuh's own test
runner, the harness changes stock rule `60000` to `decoded_as=json` and removes
its `category` requirement **inside this disposable container only**. The stock
Sysmon rule `61603`, custom rule `100001`, PCRE2 engine, and custom decoder are
then tested by native `wazuh-logtest`. Never apply this adapter to a live manager.

This validates rule predicates and inheritance with synthetic decoded fields.
It does **not** validate native Windows channel decoding, Sysmon installation,
agent delivery, or the complete endpoint-to-alert path. Check those separately
with an authorized benign endpoint smoke test and the resulting manager alert.
The CI replay must report native tests passing before claiming native validation;
an offline pass with skipped native tests is insufficient.

Sources:

- [Wazuh 4.14.7 Sysmon rules](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0595-win-sysmon_rules.xml)
- [Official JSON test adapter](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/testing/runtests.py)
- [Official manager image reference](https://github.com/wazuh/wazuh-docker/blob/v4.14.7/single-node/docker-compose.yml)
- [Wazuh logtest reference](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
