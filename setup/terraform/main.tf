terraform {
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
  description = "Wazuh Manager - dashboard, API, and agent enrollment"
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

  # Wazuh agent registration
  ingress {
    description = "Wazuh agent enrollment"
    from_port   = 1514
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.lab.cidr_block]
  }

  # Wazuh API
  ingress {
    description = "Wazuh API"
    from_port   = 55000
    to_port     = 55000
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

  # WinRM (for remote management)
  ingress {
    description = "WinRM HTTPS"
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Allow Wazuh manager to reach the agent
  ingress {
    description = "Wazuh agent communication"
    from_port   = 1514
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.lab.cidr_block]
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
# Allow all traffic between lab instances for attack simulation

resource "aws_security_group" "lab_internal" {
  name        = "lab-internal-sg"
  description = "Allow all traffic between lab instances"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "All internal lab traffic"
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
  vpc_security_group_ids = [aws_security_group.wazuh.id, aws_security_group.lab_internal.id]

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
              EOF

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
    volume_size = 50
    volume_type = "gp3"
  }

  user_data = <<-USERDATA
              <powershell>
              # Install Sysmon
              $sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
              $sysmonZip = "C:\Windows\Temp\Sysmon.zip"
              $sysmonDir = "C:\Windows\Temp\Sysmon"
              Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip
              Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force
              & "$sysmonDir\Sysmon64.exe" -accepteula -i

              # Install Wazuh agent and enroll with manager
              $wazuhUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi"
              $wazuhMsi = "C:\Windows\Temp\wazuh-agent.msi"
              Invoke-WebRequest -Uri $wazuhUrl -OutFile $wazuhMsi
              Start-Process msiexec.exe -ArgumentList "/i $wazuhMsi /q WAZUH_MANAGER='${aws_instance.wazuh_manager.private_ip}'" -Wait
              Start-Service WazuhSvc
              </powershell>
              USERDATA

  depends_on = [aws_instance.wazuh_manager]

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
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "Kali Attacker"
    Role = "attacker"
  }
}
