terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "wazuh_manager" {
  ami           = "ami-0c7217cdde317cfec" # Ubuntu 22.04 LTS (us-east-1), replace as needed
  instance_type = "t3.xlarge"             # Wazuh manager needs resources

  tags = {
    Name = "Wazuh Manager"
  }

  user_data = <<-EOF
              #!/bin/bash
              curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
              EOF
}

output "wazuh_manager_ip" {
  value = aws_instance.wazuh_manager.public_ip
}
