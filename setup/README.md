# Setup

Infrastructure and environment setup for the Threat Detection Lab.

## Contents

- `terraform/` - IaC for deploying the lab environment on AWS
- `wazuh/` - Standalone Wazuh deployment (single-instance)

## Lab Architecture

The Terraform configuration in `terraform/` deploys a full detection engineering lab:

| Instance | Purpose | Type |
|----------|---------|------|
| **Wazuh Manager** | Wazuh all-in-one (manager, indexer, dashboard) for log ingestion and SIEM | Ubuntu 22.04, t3.xlarge |
| **Windows Server** | Target host with Sysmon + Wazuh agent | Windows Server 2022, t2.medium |
| **Kali Linux** | Attack simulation and testing | Kali Linux, t2.medium |

### Network

All instances are deployed into a dedicated VPC (`10.0.0.0/16`) with:

- Public subnet with internet gateway
- Per-role security groups (Wazuh, Windows, Kali)
- Internal security group allowing all lab-to-lab traffic
- External access locked to your IP via `allowed_ip`

## Deployment

```bash
cd setup/terraform

# Copy and fill in your variables
cp terraform.tfvars.example terraform.tfvars

terraform init
terraform plan
terraform apply
```

## Requirements

- AWS credentials configured (`aws configure` or environment variables)
- An existing EC2 key pair
- Variables set in `terraform.tfvars`:
  - `aws_region` - AWS region (default: `us-east-1`)
  - `ubuntu_ami` - AMI for Ubuntu 22.04 LTS (Wazuh Manager)
  - `windows_ami` - AMI for Windows Server 2022
  - `kali_ami` - AMI for Kali Linux
  - `key_name` - EC2 key pair name
  - `allowed_ip` - Your public IP in CIDR notation (e.g. `203.0.113.10/32`)

## Post-Deployment

1. **Wazuh Dashboard** - Access at `https://<wazuh_public_ip>`. Default credentials are printed during install (check `/var/log/cloud-init-output.log` on the instance).
2. **Windows Target** - RDP in and verify Sysmon and Wazuh agent are running. The agent auto-enrolls with the Wazuh Manager.
3. **Kali Linux** - SSH in to run attack simulations against the Windows target.

## Teardown

```bash
terraform destroy
```
