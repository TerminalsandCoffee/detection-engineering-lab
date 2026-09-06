terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- Networking ---

resource "aws_vpc" "lab" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "detection-lab-vpc"
  }
}

resource "aws_subnet" "lab" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name = "detection-lab-subnet"
  }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id

  tags = {
    Name = "detection-lab-igw"
  }
}

resource "aws_route_table" "lab" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = {
    Name = "detection-lab-rt"
  }
}

resource "aws_route_table_association" "lab" {
  subnet_id      = aws_subnet.lab.id
  route_table_id = aws_route_table.lab.id
}

# --- Security Groups ---

resource "aws_security_group" "wazuh" {
  name        = "wazuh-manager-sg"
  description = "Wazuh Manager - administrator SSH/dashboard and target agent connections"
  vpc_id      = aws_vpc.lab.id

  # SSH
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Wazuh dashboard
  ingress {
    description = "Wazuh Dashboard (HTTPS)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Agents initiate connections to the manager; restrict them to the target role.
  ingress {
    description     = "Wazuh agent communication and enrollment from Windows target"
    from_port       = 1514
    to_port         = 1515
    protocol        = "tcp"
    security_groups = [aws_security_group.windows.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "wazuh-manager-sg"
  }
}

resource "aws_security_group" "windows" {
  name        = "windows-target-sg"
  description = "Windows Server - RDP and Wazuh agent traffic"
  vpc_id      = aws_vpc.lab.id

  # RDP
  ingress {
    description = "RDP"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "windows-target-sg"
  }
}

resource "aws_security_group" "kali" {
  name        = "kali-attacker-sg"
  description = "Kali Linux - SSH and attack simulation"
  vpc_id      = aws_vpc.lab.id

  # SSH
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "kali-attacker-sg"
  }
}

# --- Lab internal traffic ---
# Allow traffic between Kali and Windows for attack simulation, not to the SIEM.

resource "aws_security_group" "lab_internal" {
  name        = "lab-internal-sg"
  description = "Allow attack traffic between Kali and Windows only"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "Traffic between attack and target hosts"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "lab-internal-sg"
  }
}

# --- EC2 Instances ---

resource "aws_instance" "wazuh_manager" {
  ami                    = var.ubuntu_ami
  instance_type          = var.wazuh_instance_type
  key_name               = var.key_name
  subnet_id              = aws_subnet.lab.id
  vpc_security_group_ids = [aws_security_group.wazuh.id]

  root_block_device {
    volume_size           = var.wazuh_volume_size
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  user_data = templatefile("${path.module}/scripts/install-wazuh.sh.tftpl", {
    wazuh_branch = var.wazuh_branch
  })
  # EC2 user data runs on first boot; replacement makes bootstrap changes explicit.
  user_data_replace_on_change = true

  depends_on = [aws_route_table_association.lab]

  tags = {
    Name = "Wazuh Manager"
    Role = "siem"
  }
}

resource "aws_instance" "windows_target" {
  ami                    = var.windows_ami
  instance_type          = var.windows_instance_type
  key_name               = var.key_name
  subnet_id              = aws_subnet.lab.id
  vpc_security_group_ids = [aws_security_group.windows.id, aws_security_group.lab_internal.id]

  root_block_device {
    volume_size           = 50
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  user_data = templatefile("${path.module}/scripts/install-windows.ps1.tftpl", {
    manager_ip           = aws_instance.wazuh_manager.private_ip
    wazuh_agent_version  = var.wazuh_agent_version
    sysmon_config_base64 = filebase64("${path.module}/sysmon-lab.xml")
  })
  user_data_replace_on_change = true

  # Resource ordering alone does not wait for the manager's installer to finish.
  depends_on = [aws_instance.wazuh_manager]

  lifecycle {
    precondition {
      condition     = startswith(var.wazuh_agent_version, "${var.wazuh_branch}.")
      error_message = "Use a Windows agent version from the selected Wazuh manager branch."
    }
  }

  tags = {
    Name = "Windows Target"
    Role = "target"
  }
}

resource "aws_instance" "kali_attacker" {
  ami                    = var.kali_ami
  instance_type          = var.kali_instance_type
  key_name               = var.key_name
  subnet_id              = aws_subnet.lab.id
  vpc_security_group_ids = [aws_security_group.kali.id, aws_security_group.lab_internal.id]

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "Kali Attacker"
    Role = "attacker"
  }
}
