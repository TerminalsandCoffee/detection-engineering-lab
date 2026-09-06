# Historical standalone Wazuh example

This directory preserves the original single-instance example and its URL for existing blog readers. Its `main.tf` is historical: it assumes an account's default networking, has no configured administrator access, and references Wazuh 4.9 and an old regional AMI. It is not the maintained lab deployment.

For the current Wazuh + Windows + Kali lab, follow the [setup guide](../../README.md) and use [`setup/terraform`](../../terraform/). The maintained configuration includes an explicit VPC, restricted management access, encrypted disks, bootstrap checks, and Windows telemetry collection.

Do not apply both configurations to the same Terraform state. If you already deployed this standalone example, keep its state and review any migration or teardown separately; the maintained lab uses different infrastructure and is not an automatic state migration.
