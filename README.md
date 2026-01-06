# NetPi-Scanner

**Team Members:** Aiden Jajo, Diego Lopez, Manuel Jimenez, Romel Aleman  
**School:** San Diego State University  
**Course:** CS576-03 - Computer Networks and Distributed Systems  
**Semester:** Fall 2024

---

## Overview

NetPi-Scanner is a network monitoring and analysis tool designed for Raspberry Pi. This team project provides network administrators with automated device discovery, performance testing, packet capture with MITM capabilities, and an intuitive Flask-based web interface.

## System Architecture

![Execution Flowchart](execution_flowchart.png)

*Figure: NetPi-Scanner system workflow showing initialization, configuration, automated scheduling, and web interface interactions.*

---

## Key Features

- **Network Scanning:** Automated device discovery with Nmap, MAC address resolution, and hostname lookup
- **Performance Monitoring:** ICMP ping tests, TCP connection timing, bandwidth measurement, and port scanning
- **Packet Analysis:** Real-time traffic capture with Scapy, protocol distribution analysis, and ARP spoofing for MITM
- **Web Interface:** Modern Flask-based UI with real-time updates, interactive dashboards, and CSV report downloads
- **Automation:** Configurable cron jobs for scheduled scanning and performance monitoring

---

## Technology Stack

**Backend:** Python 3, Flask, Nmap, Scapy  
**Frontend:** HTML5, CSS3, JavaScript  
**System:** Bash, Cron, Linux/Raspberry Pi OS

---

## Installation

### Prerequisites
- Raspberry Pi (or Linux system)
- Python 3.x
- Root/sudo access

### Setup

1. **Clone the repository:**
```bash
   git clone https://github.com/aidenjajo/CS576-NetPi-Scanner.git
   cd CS576-NetPi-Scanner
```

2. **Run initialization:**
```bash
   sudo ./init.py
```
   
   This will:
   - Install required packages (nmap, scapy, Flask)
   - Configure network settings
   - Set up automated cron jobs
   - Launch the web interface

3. **Access the web interface:**
```
   http://[RASPBERRY_PI_IP]:1234
```

---

## Usage

### Web Interface

**Network Scanning:**
- Navigate to "Scan Network" and click "Start Scan"
- View discovered devices with IP, MAC, hostname, and active status

**Performance Testing:**
- Navigate to "Performance Test" and click "Start Benchmarks"
- View ICMP latency, TCP timing, bandwidth, and open ports

**Packet Capture:**
- Navigate to "Packet Sniffer"
- Configure duration, protocol filters, and target devices
- Optionally enable MITM mode for specific device capture
- View detailed analysis in "View Past Captures & Analysis"

**Reports:**
- Download CSV files for all scans and performance logs
- Access scheduled task logs

### Command-Line Interface
```bash
# Network operations
python3 netpi.py --scan              # Discover devices
python3 netpi.py --performance       # Test performance
python3 netpi.py --webui             # Launch web UI

# Configuration
python3 netpi.py --update-config     # Update network settings

# Maintenance
python3 netpi.py --delete-devices    # Clear device cache
python3 netpi.py --delete-performance # Clear performance cache
```

---

## Project Structure
```
CS576-NetPi-Scanner/
├── Functions/              # Core networking modules
│   ├── arp_spoof.py       # MITM capabilities
│   ├── scan.py            # Device discovery
│   ├── peformance.py      # Performance testing
│   └── sniffer.py         # Packet capture
├── WebUI/                  # Flask web interface
│   ├── host.py            # Server and routes
│   └── *.html             # UI templates
├── CSV/                    # Data storage
├── scheduled_logs/         # Automated task logs
├── init.py                # Setup script
├── netpi.py               # CLI interface
└── cronjob_setup.sh       # Automation configuration
```

---

## Technical Highlights

- **Nmap Integration:** Reliable device discovery with MAC/hostname resolution
- **Scapy Framework:** Low-level packet manipulation for ARP spoofing and traffic analysis
- **Flask Architecture:** Modern web interface with AJAX for real-time updates
- **MITM Capabilities:** ARP poisoning for targeted packet interception
- **Statistical Analysis:** Packet loss calculation, RTT measurements, bandwidth testing

---

## License

This project was developed as part of CS576 coursework at San Diego State University.

---

## Acknowledgments

- CS576-03 Faculty, San Diego State University
- Open source libraries: Nmap, Scapy, Flask

---

*Network monitoring and analysis for Raspberry Pi*
