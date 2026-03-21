variable "aws_region" {
  description = "AWS region for lab deployment"
  type        = string
  default     = "us-east-1"
}

variable "ubuntu_ami" {
  description = "AMI ID for Ubuntu 22.04 LTS (Wazuh Manager)"
  type        = string

  validation {
    condition     = can(regex("^ami-[a-z0-9]+$", var.ubuntu_ami))
    error_message = "ubuntu_ami must be a valid AMI ID (for example ami-0123456789abcdef0)."
  }
}

variable "windows_ami" {
  description = "AMI ID for Windows Server 2022 (target host)"
  type        = string

  validation {
    condition     = can(regex("^ami-[a-z0-9]+$", var.windows_ami))
    error_message = "windows_ami must be a valid AMI ID (for example ami-0123456789abcdef0)."
  }
}

variable "kali_ami" {
  description = "AMI ID for Kali Linux (attack simulation)"
  type        = string

  validation {
    condition     = can(regex("^ami-[a-z0-9]+$", var.kali_ami))
    error_message = "kali_ami must be a valid AMI ID (for example ami-0123456789abcdef0)."
  }
}

variable "key_name" {
  description = "Name of the AWS key pair for SSH/RDP access"
  type        = string
}

variable "allowed_ip" {
  description = "Your public IP in CIDR notation for access control (e.g. 203.0.113.10/32)"
  type        = string

  validation {
    condition     = can(cidrhost(var.allowed_ip, 0)) && !contains(["0.0.0.0/0", "::/0"], var.allowed_ip)
    error_message = "allowed_ip must be a valid single-admin CIDR and must not allow global access."
  }
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
