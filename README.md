# CodeAlpha Internship - Cyber Security

## TASK 1: Basic Network Sniffer

This repository contains the implementation of a **Basic Network Sniffer** developed during my Cyber Security Internship at **CodeAlpha**.

### 📌 Project Overview
A network sniffer is a tool used to intercept and log traffic that passes over a digital network. This Python-based application captures network traffic packets in real-time and analyzes their structure, showing key components such as protocols, source/destination IP addresses, and payload data.

### ⚙️ Features
- **Packet Capturing:** Captures incoming and outgoing network traffic.
- **Protocol Identification:** Detects and classifies common protocols like TCP, UDP, and ICMP.
- **Address Tracking:** Extracts and displays Source and Destination IP addresses.
- **Port Analysis:** Identifies source and destination ports for TCP and UDP packets.
- **Payload Extraction:** Inspects and shows raw payload data contained within packets.

### 🛠️ Prerequisites & Installation
To run this project on Windows, you need to install **Python** and a packet capture library wrapper.

1. **Install Npcap:**
   Download and install Npcap from [https://npcap.com/](https://npcap.com/). Make sure to check the option *"Install Npcap in WinPcap API-compatible Mode"* during installation.

2. **Install Scapy:**
   Open Command Prompt (CMD) and run:
   ```bash
   pip install scapy
``



------------------




**Disclaimer**
  This tool is developed strictly for educational and security research purposes as part of the CodeAlpha Internship           program. Unauthorized network sniffing or capturing data on networks without explicit permission is illegal and unethical.

Developed by:Ritika Karak

Internship Role: Cyber Security Intern at CodeAlpha
