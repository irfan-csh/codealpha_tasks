# Network Intrusion Detection & Automated Response System

## CodeAlpha Cybersecurity Internship Project

### Overview
This project demonstrates the deployment of a Network Intrusion Detection System (NIDS) using Suricata on Ubuntu Linux. The system monitors network traffic, detects suspicious activity, and performs automated response actions by blocking malicious IP addresses using iptables.

### Technologies Used
- Ubuntu Linux
- Suricata IDS
- Kali Linux
- Nmap
- Bash Scripting
- iptables
- VirtualBox

### Features
- ICMP Ping Detection
- SYN Port Scan Detection
- SSH Connection Monitoring
- HTTP Traffic Detection
- Telnet Detection
- Automated IP Blocking
- Real-Time Alert Monitoring

### Project Structure

```text
CodeAlpha_Network_IDS
├── report
├── rules
└── screenshots
```

### Key Commands Used

#### Suricata Installation

```bash
sudo apt update
sudo apt install suricata -y
```

#### Verify Installation

```bash
suricata --build-info
```

#### Test Suricata Configuration

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

#### Run Suricata

```bash
sudo suricata -i enp0s3 -c /etc/suricata/suricata.yaml
```

#### Monitor Alerts

```bash
sudo tail -f /var/log/suricata/fast.log
```

#### Monitor Detailed Events

```bash
sudo tail -f /var/log/suricata/eve.json
```

#### Edit Custom Rules

```bash
sudo nano /etc/suricata/rules/local.rules
```

#### Generate ICMP Traffic

```bash
ping <TARGET_IP>
```

#### Generate Port Scan Traffic

```bash
nmap -sS <TARGET_IP>
```

#### Generate HTTP Traffic

```bash
curl http://example.com
```

#### View Firewall Rules

```bash
sudo iptables -L INPUT -n --line-numbers
```

#### Flush Firewall Rules

```bash
sudo iptables -F INPUT
```

#### Run Automated Response Script

```bash
chmod +x autoblock.sh
sudo ./autoblock.sh
```

### Project Outcome

Successfully deployed a Suricata-based Network Intrusion Detection System capable of detecting network reconnaissance and suspicious activities in real time. The project was further enhanced with an automated response mechanism that dynamically blocks malicious IP addresses using iptables, demonstrating practical IDS/IPS functionality and SOC-oriented incident response capabilities.

### Author
Irfan csh
