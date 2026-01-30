output "wazuh_manager_public_ip" {
  description = "Public IP of the Wazuh Manager"
  value       = aws_instance.wazuh_manager.public_ip
}

output "wazuh_manager_private_ip" {
  description = "Private IP of the Wazuh Manager (used for agent enrollment)"
  value       = aws_instance.wazuh_manager.private_ip
}

output "wazuh_dashboard_url" {
  description = "Wazuh dashboard URL"
  value       = "https://${aws_instance.wazuh_manager.public_ip}"
}

output "windows_target_public_ip" {
  description = "Public IP of the Windows Server target"
  value       = aws_instance.windows_target.public_ip
}

output "windows_target_private_ip" {
  description = "Private IP of the Windows Server target"
  value       = aws_instance.windows_target.private_ip
}

output "kali_attacker_public_ip" {
  description = "Public IP of the Kali Linux attacker"
  value       = aws_instance.kali_attacker.public_ip
}

output "kali_attacker_private_ip" {
  description = "Private IP of the Kali Linux attacker"
  value       = aws_instance.kali_attacker.private_ip
}

output "vpc_id" {
  description = "VPC ID for the lab environment"
  value       = aws_vpc.lab.id
}
