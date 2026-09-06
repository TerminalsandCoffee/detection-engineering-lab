#!/usr/bin/env bash
# Offline fixture replay in an ephemeral official Wazuh manager container.
set -euo pipefail

if [[ "${1:-}" != "--inside-container" ]]; then
  repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
  image='wazuh/wazuh-manager:4.14.7@sha256:80cada6a192fcb8caa8b415a5b64e2155138dd8df1da3a7b227d7e5e4e7460c0'
  exec docker run --rm --network none --ulimit nofile=655360:655360 \
    --mount "type=bind,source=${repo_root},target=/work,readonly" \
    --entrypoint /bin/bash "$image" /work/tests/wazuh_logtest.sh --inside-container
fi

# Never initialize a host manager. The repository is mounted read-only.
[[ -f /.dockerenv && -d /var/ossec/data_tmp ]] || {
  printf '%s\n' 'This branch requires the fresh official Docker image.' >&2
  exit 1
}

# Restore the image's packaged configuration snapshots without invoking its
# service entrypoint (which would also start collectors and other components).
cp -a /var/ossec/data_tmp/permanent/. /
cp -a /var/ossec/data_tmp/exclusion/. /
# Match the official image's initialization permissions so analysisd can rebuild
# the packaged CDB lists when their source files are newer than the databases.
chown -R wazuh:wazuh /var/ossec/etc/lists /var/ossec/queue/rids
cp /work/detections/wazuh-rules/powershell_exec_via_bat.xml /var/ossec/etc/rules/
cp /work/detections/decoders/local_decoder.xml /var/ossec/etc/decoders/
chown root:wazuh /var/ossec/etc/rules/powershell_exec_via_bat.xml /var/ossec/etc/decoders/local_decoder.xml
chmod 640 /var/ossec/etc/rules/powershell_exec_via_bat.xml /var/ossec/etc/decoders/local_decoder.xml

python_bin=/var/ossec/framework/python/bin/python3
"$python_bin" - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET

# Same JSON test adapter used by Wazuh's official ruleset/testing/runtests.py.
# Only the disposable image's rule 60000 changes; the shipped detection and
# Sysmon parent 61603 are loaded unchanged. This does not test agent decoding.
base_path = Path('/var/ossec/ruleset/rules/0575-win-base_rules.xml')
base_tree = ET.parse(base_path)
base_rule = base_tree.getroot().find("rule[@id='60000']")
assert base_rule is not None
for tag in ('category', 'decoded_as'):
    for element in base_rule.findall(tag):
        base_rule.remove(element)
ET.SubElement(base_rule, 'decoded_as').text = 'json'
base_tree.write(base_path, encoding='unicode')

# Keep packaged rules/decoders/lists, but load only this repository's custom rule
# to avoid a collision with the manager package's sample local rule 100001.
config_path = Path('/var/ossec/etc/ossec.conf')
wrapped = ET.fromstring('<config>' + config_path.read_text() + '</config>')
rulesets = wrapped.findall('ossec_config/ruleset')
assert rulesets, 'Packaged manager ruleset configuration not found'
for ruleset in rulesets:
    for element in list(ruleset):
        if element.tag in ('rule_dir', 'rule_include') and (element.text or '').strip().startswith('etc/rules'):
            ruleset.remove(element)
ET.SubElement(rulesets[0], 'rule_include').text = 'etc/rules/powershell_exec_via_bat.xml'
config_path.write_text('\n'.join(ET.tostring(element, encoding='unicode') for element in wrapped))
PY

/var/ossec/bin/wazuh-analysisd -t > /tmp/wazuh-config-check.log 2>&1 || {
  cat /tmp/wazuh-config-check.log >&2
  exit 1
}
cat /tmp/wazuh-config-check.log
# Some initialization errors do not produce a nonzero exit code in Wazuh.
if grep -Eq 'ERROR:|CRITICAL:' /tmp/wazuh-config-check.log; then
  exit 1
fi
# Only the analysis engine and its local database run. No agents, API, active
# response, inventory or scanner service starts; the container has no network.
/var/ossec/bin/wazuh-db -f > /tmp/wazuh-db.log 2>&1 &
db_pid=$!
/var/ossec/bin/wazuh-analysisd -f > /tmp/wazuh-analysisd.log 2>&1 &
analysis_pid=$!
trap 'kill "$analysis_pid" "$db_pid" 2>/dev/null || true' EXIT

for attempt in $(seq 1 30); do
  [[ -S /var/ossec/queue/sockets/logtest ]] && break
  if ! kill -0 "$analysis_pid" 2>/dev/null; then
    cat /tmp/wazuh-analysisd.log >&2
    exit 1
  fi
  sleep 1
done
[[ -S /var/ossec/queue/sockets/logtest ]] || {
  cat /tmp/wazuh-analysisd.log >&2
  printf '%s\n' 'Timed out waiting for the native logtest socket.' >&2
  exit 1
}

export WAZUH_LOGTEST=/var/ossec/bin/wazuh-logtest
export PYTHONDONTWRITEBYTECODE=1
cd /work
"$python_bin" -m unittest discover -s tests -p test_wazuh_rules.py -v
