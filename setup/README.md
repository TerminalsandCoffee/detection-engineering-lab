# Setup

The maintained deployment is [`terraform/`](terraform/): a small AWS lab with a Wazuh all-in-one server, a Windows target, and a Kali host. [`wazuh/tf-deployment/`](wazuh/tf-deployment/) preserves the historical standalone example for existing blog links; use its README before following that older code.

These configurations are learning infrastructure. Static validation checks syntax and configuration relationships; it does not establish that an AMI is available, a package installs successfully, or an event reaches the SIEM. Verify the post-deployment checks below before testing detections.

## Lab Architecture

| Instance | Purpose | Default sizing |
|----------|---------|----------------|
| **Wazuh Manager** | Manager, indexer, and dashboard on one Ubuntu 22.04 x86_64 host | t3.xlarge, 50 GiB encrypted gp3 |
| **Windows Server** | Windows Server 2022 x86_64 with Sysmon and Wazuh agent | t2.medium, 50 GiB encrypted gp3 |
| **Kali Linux** | Official Kali x86_64 image for authorized lab testing | t2.medium, 30 GiB encrypted gp3 |

The Wazuh defaults were checked against official documentation on **6 September 2026**: installation-assistant branch **4.14**, Windows agent **4.14.7** (MSI revision 1). The branch installer selects its current patch release, so this is not a completely pinned machine image. Keep the manager at the same or a later version than the agent. Wazuh recommends 4 vCPU, 8 GiB RAM, and 50 GB storage for 1–25 agents in its [quickstart](https://documentation.wazuh.com/current/quickstart.html); noisy lab telemetry and longer retention can require more storage.

### Network and access

All instances use a dedicated VPC (`10.0.0.0/16`) and public subnet (`10.0.1.0/24`) with an internet gateway.

- `allowed_ip` must be one **IPv4 `/32`**. It permits SSH to Wazuh/Kali, HTTPS to the dashboard, and RDP to Windows.
- The Windows target can reach Wazuh TCP **1514** for events and **1515** for enrollment. The agent initiates both connections; Windows does not need inbound listeners on those ports.
- Kali and Windows share an internal security group for attack traffic. The Wazuh server is excluded from that group. AWS [combines the allow rules of every attached security group](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html), so a restrictive role group cannot override a broad shared group.
- Wazuh API port 55000, indexer port 9200, and WinRM are not opened to the administrator's public IP. The all-in-one dashboard accesses its local components.
- Outbound internet access remains open for installation and lab use. This is not a malware-containment network; restrict egress and isolate further before changing the threat model. Guest firewalls still apply.

EC2 instances, storage, and public IPv4 addresses incur AWS charges. Use a dedicated lab account, track its costs, and remove infrastructure when finished.

## Validate without deploying

Install Terraform **1.5 or newer**, then run:

```bash
cd setup/terraform
terraform fmt -check
terraform init -backend=false
terraform validate
```

`init` downloads the provider; `validate` checks configuration without using AWS credentials or calling AWS services. No `terraform.tfvars` file is needed for these checks. Keep the generated dependency lockfile with a reviewed deployment to retain the provider selection.

From the repository root, the local setup tests can also be run with Python 3.11+:

```bash
python -m unittest discover -s tests -p "test_setup.py" -v
```

Some tests use a locally installed Terraform CLI to render templates without providers, or PowerShell to parse and exercise a configuration helper; they report a skip when those tools are unavailable. They never launch instances or execute the bootstrap installers.

`terraform plan` is a separate AWS-connected operation. Even `plan -refresh=false` can initialize the provider and make API requests; it is not an offline validation flag and can hide external changes. See the [Terraform plan reference](https://developer.hashicorp.com/terraform/cli/commands/plan).

## Prepare a deployment

1. Configure AWS credentials for the intended lab account and region. Confirm that account before using Terraform.
2. Select current, publisher-verified **x86_64** AMIs for Ubuntu 22.04, Windows Server 2022, and Kali in that region. AMI IDs are [region-specific](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-systems-manager-parameter-to-find-AMI.html); the example deliberately supplies no reusable AMI IDs. Check instance compatibility and the subnet's `${aws_region}a` availability zone. Official Kali images can require [AWS Marketplace subscription](https://www.kali.org/docs/cloud/aws/).
3. Choose an existing EC2 key pair in the same region and keep its private key available for SSH and Windows Administrator password decryption.
4. Copy `terraform.tfvars.example` to `terraform.tfvars` and replace every placeholder. On PowerShell, use `Copy-Item terraform.tfvars.example terraform.tfvars`.

| Input | Meaning |
|-------|---------|
| `aws_region` | AWS region; defaults to `us-east-1` |
| `ubuntu_ami`, `windows_ami`, `kali_ami` | Verified regional image IDs; no defaults |
| `key_name` | Existing EC2 key-pair name |
| `allowed_ip` | Your current public IPv4 address with `/32` |
| `wazuh_branch`, `wazuh_agent_version` | Compatible manager branch and exact Windows agent release |
| `wazuh_volume_size` | Wazuh disk size in GiB, at least 50 |
| `*_instance_type` | Optional sizing overrides; retain x86_64 compatibility |

When you deliberately want to create infrastructure, review an AWS-connected plan and its costs before applying it. Protect Terraform state, variable files, and saved plans; do not commit credentials or local state.

Existing users should review changes carefully. Resource names and original input names are preserved, but updated access rules take effect on apply. The Wazuh and Windows EC2 resources set `user_data_replace_on_change = true`: changing a bootstrap template can **replace the instance and delete its root disk**. The old standalone directory has separate state and is not automatically migrated.

## Bootstrap and readiness

Terraform creates EC2 resources before guest installation necessarily finishes. `depends_on` establishes resource order, not Wazuh readiness. The manager waits for its internet route; the Windows bootstrap separately retries enrollment-port connectivity for up to 20 minutes. Downloads and MSI exits are checked, and failures are recorded in logs.

### Wazuh server

Connect as the Ubuntu AMI's administrator and inspect:

```bash
sudo cloud-init status --wait
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard --no-pager
sudo cat /var/lib/detection-lab/wazuh-bootstrap-complete
sudo tail -n 80 /var/log/cloud-init-output.log
```

The completion marker is written only after the installer and service checks succeed. Installation credentials are generated on the instance; inspect the installer output or retrieve them privately from:

```bash
sudo tar -O -xf /opt/wazuh-installation/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Treat that archive and the installation logs as sensitive. Access the URL from the `wazuh_dashboard_url` Terraform output. The quickstart uses a self-signed certificate; confirm the expected endpoint before accepting it.

### Windows target

Use the EC2 console and your key pair to retrieve/decrypt the Administrator password, then RDP to `windows_target_public_ip`. In an administrative PowerShell session:

```powershell
Get-Service Sysmon64, WazuhSvc
Get-Content C:\ProgramData\DetectionLab\windows-bootstrap-complete.txt
Get-Content C:\ProgramData\DetectionLab\bootstrap.log -Tail 60
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 60
```

If no bootstrap log exists, inspect EC2Launch v2's `C:\ProgramData\Amazon\EC2Launch\log\agent.log`, or the launch-agent-specific location in the [AWS user-data documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html). An MSI reboot request is logged; verify services again after rebooting. A running service is not proof of enrollment: confirm the agent is **Active** in the dashboard and check the manager/agent logs.

### Verify telemetry before detections

[`sysmon-lab.xml`](terraform/sysmon-lab.xml) explicitly enables process creation (1), network connections (3), file creation (11), and registry events (12–14). The bootstrap adds `Microsoft-Windows-Sysmon/Operational` as an `eventchannel` source in the agent's `ossec.conf`. Installing Sysmon alone does not enable this Wazuh subscription; network events are also disabled in Sysmon's default configuration. See [Microsoft's Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and [Wazuh Windows event collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html).

Generate a benign process and look for the local event:

```powershell
cmd.exe /c echo detection-lab-smoke-test
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 5 |
    Select-Object TimeCreated, Id, Message
```

Next confirm that the corresponding event reaches Wazuh using the agent/manager logs and a matching native rule. Wazuh indexes alerts by default, so an ordinary event with no alerting rule may not appear in the alerts index. The repository's portable TOML queries require an appropriate query engine/field mapping; Terraform does not import or convert them. Follow the [detection documentation](../detections/README.md) for native Wazuh rule installation and validation.

After installing native rule **100001** on the manager, run this harmless batch/PowerShell smoke action on the Windows target:

```powershell
$smokeBatch = Join-Path $env:TEMP 'detection-lab-smoke.bat'
@'
@echo off
powershell.exe -NoProfile -Command "Write-Output 'detection-lab-smoke-100001'"
'@ | Set-Content -LiteralPath $smokeBatch -Encoding ASCII
cmd.exe /c $smokeBatch
```

Confirm a new alert with **rule ID 100001**, **Sysmon event ID 1**, this target's agent identity, and the **`detection-lab-smoke-100001`** command-line marker. This is the delivery check; local fixture tests do not prove endpoint ingestion. Keep the batch file out of production workflows and remove the exact file when finished.

### Kali host

SSH using the username documented for the chosen official image. Cloud images may not include every tool; install only the tools needed for your authorized lab exercise. Target the Windows private IP and keep activity inside the lab's defined scope.

## Teardown

Back up only the lab data you need, confirm the current directory/workspace/account, and review the resources Terraform proposes to destroy:

```bash
cd setup/terraform
terraform destroy
```

Confirm that the lab resources have been removed in AWS. Destroying this configuration deletes its EC2 root volumes and local SIEM data.
