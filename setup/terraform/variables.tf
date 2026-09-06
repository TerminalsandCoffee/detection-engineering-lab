variable "aws_region" {
  description = "AWS region for lab deployment"
  type        = string
  default     = "us-east-1"
}

variable "ubuntu_ami" {
  description = "AMI ID for Ubuntu 22.04 LTS (Wazuh Manager)"
  type        = string

  validation {
    condition     = can(regex("^ami-([0-9a-f]{8}|[0-9a-f]{17})$", var.ubuntu_ami))
    error_message = "ubuntu_ami must be a valid AMI ID (for example ami-0123456789abcdef0)."
  }
}

variable "windows_ami" {
  description = "AMI ID for Windows Server 2022 (target host)"
  type        = string

  validation {
    condition     = can(regex("^ami-([0-9a-f]{8}|[0-9a-f]{17})$", var.windows_ami))
    error_message = "windows_ami must be a valid AMI ID (for example ami-0123456789abcdef0)."
  }
}

variable "kali_ami" {
  description = "AMI ID for Kali Linux (attack simulation)"
  type        = string

  validation {
    condition     = can(regex("^ami-([0-9a-f]{8}|[0-9a-f]{17})$", var.kali_ami))
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
    condition     = can(cidrnetmask(var.allowed_ip)) && can(regex("/32$", var.allowed_ip))
    error_message = "allowed_ip must be one valid IPv4 address with /32; IPv6 and wider networks are not supported."
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

variable "wazuh_branch" {
  description = "Wazuh installation-assistant branch; check the official quickstart before changing"
  type        = string
  default     = "4.14"

  validation {
    condition     = can(regex("^4\\.[0-9]+$", var.wazuh_branch))
    error_message = "wazuh_branch must be a 4.x release branch, such as 4.14."
  }
}

variable "wazuh_agent_version" {
  description = "Exact Windows Wazuh agent version (MSI revision 1); keep within the manager branch"
  type        = string
  default     = "4.14.7"

  validation {
    condition     = can(regex("^4\\.[0-9]+\\.[0-9]+$", var.wazuh_agent_version))
    error_message = "wazuh_agent_version must be a 4.x.y version, such as 4.14.7."
  }
}

variable "wazuh_volume_size" {
  description = "Wazuh root volume in GiB; quickstart recommends at least 50 GB for 1-25 agents"
  type        = number
  default     = 50

  validation {
    condition     = var.wazuh_volume_size >= 50 && var.wazuh_volume_size == floor(var.wazuh_volume_size)
    error_message = "wazuh_volume_size must be a whole number of GiB of at least 50."
  }
}
