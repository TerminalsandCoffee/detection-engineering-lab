variable "aws_region" {
  description = "AWS region for lab deployment"
  type        = string
  default     = "us-east-1"
}

variable "ubuntu_ami" {
  description = "AMI ID for Ubuntu 22.04 LTS (Wazuh Manager)"
  type        = string
}

variable "windows_ami" {
  description = "AMI ID for Windows Server 2022 (target host)"
  type        = string
}

variable "kali_ami" {
  description = "AMI ID for Kali Linux (attack simulation)"
  type        = string
}

variable "key_name" {
  description = "Name of the AWS key pair for SSH/RDP access"
  type        = string
}

variable "allowed_ip" {
  description = "Your public IP in CIDR notation for access control (e.g. 203.0.113.10/32)"
  type        = string
}

variable "wazuh_instance_type" {
  description = "Instance type for the Wazuh Manager"
  type        = string
  default     = "t3.xlarge"
}

variable "windows_instance_type" {
  description = "Instance type for the Windows Server"
  type        = string
  default     = "t2.medium"
}

variable "kali_instance_type" {
  description = "Instance type for the Kali Linux instance"
  type        = string
  default     = "t2.medium"
}
