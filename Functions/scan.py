#!/usr/bin/env python3

"""
Team Members: Aiden Jajo, Diego Lopez, Manuel Jimenez, Romel Aleman
School: San Diego State University
Course: CS576-03 - Computer Networks and Distributed Systems
Project: NetPi-Scanner

Network scanning implementation using Nmap and Scapy.
Discovers active devices on the network, retrieves MAC addresses and hostnames,
and stores results in CSV format for later use.
"""

import nmap, os, csv, socket
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1

# Global configuration dictionary
config = {}

def setup_config():
    """Load configuration from .config file into global config dictionary"""
    # loop through each line in .config
    with open('.config') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            key, value = line.split('=', 1)
            config[key.strip()] = value.strip()
    # normalize older key name `router` to the canonical `address`
    if 'router' in config and 'address' not in config:
        config['address'] = config['router']

def scan_network(addr, dns_addr, subnet='24'):
    """Scan network for active devices using Nmap"""
    # Initialize Nmap port scanner
    nm = nmap.PortScanner()

    # Format address with subnet
    addr = f"{addr}/{subnet}"
    
    # Perform ping scan to discover hosts
    nm.scan(hosts=addr, arguments='-sn')  # Ping scan

    print (f"Scanning network: {addr}")

    devices = []
    # Process each discovered host
    for host in nm.all_hosts():
        ip = host
        # Extract MAC address if available
        mac = nm[host]['addresses'].get('mac', 'N/A')
        # prefer nmap-discovered hostname, fall back to reverse DNS (PTR) lookup
        hostname = get_hostname(ip, dns_addr)
        if not hostname:
            try:
                # Try standard socket hostname resolution
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = 'N/A'
        # Check if device is currently active
        active = nm[host].state() == 'up'

        # Add device to list
        devices.append({'IP': ip, 'MAC': mac, 'Hostname': hostname, 'Active': active})

    return devices

def get_hostname(ip, dns_addr=None):
    """Perform reverse DNS lookup to get hostname for an IP address"""
 
    # Use Cloudflare DNS if no DNS server specified
    if not dns_addr:
        dns_addr = '1.1.1.1'

    # Validate IP address format
    parts = ip.split('.')
    if len(parts) != 4:
        return None

    # Build reverse DNS query name (e.g., 1.0.168.192.in-addr.arpa)
    rev = ".".join(parts[::-1]) + ".in-addr.arpa"

    try:
        # Create and send DNS PTR query
        query = IP(dst=dns_addr) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=rev, qtype='PTR'))
        resp = sr1(query, timeout=1, verbose=False)
        if not resp or not resp.haslayer(DNS) or resp[DNS].ancount == 0:
            return None

        # Extract hostname from DNS response
        ans = resp[DNS].an
        # scapy returns first answer in ans; extract rdata
        rdata = getattr(ans, 'rdata', None)
        if rdata is None:
            return None
        if isinstance(rdata, bytes):
            try:
                rdata = rdata.decode()
            except Exception:
                rdata = None
        if isinstance(rdata, str):
            return rdata.rstrip('.')

    except Exception:
        return None

    return None

def load_devices(filename='CSV/saved_devices.csv'):
    """Load previously saved devices from CSV file"""
    devices = []
    if os.path.exists(filename):
        # Read devices from CSV
        with open(filename, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                devices.append(row)
    return devices

def save_devices(new_devices, filename='CSV/saved_devices.csv'):
    """Save or update devices in CSV file"""
    # Load existing devices
    existing_devices = load_devices(filename)

    # Create a dictionary for easy lookup by MAC address
    device_dict = {device['MAC']: device for device in existing_devices}

    # Update existing devices and add new ones
    for device in new_devices:
        mac = device['MAC']
        if mac in device_dict:
            # Update existing device
            device_dict[mac].update(device)  # Update existing attributes
        else:
            # Add new device
            device_dict[mac] = device

    # Ensure CSV directory exists, then write updated device list back to file
    dirname = os.path.dirname(filename)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname, exist_ok=True)

    # Write all devices to CSV
    with open(filename, 'w', newline='') as f:
        fieldnames = ['IP', 'MAC', 'Hostname', 'Active']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(device_dict.values())

def update_config():
    """Update configuration file with new network settings"""
    # Make prompts/validation match init.py's behavior (router, subnet, dns)
    entry_list = [
        "router",
        "subnet",
        "dns"
    ]

    defaults = [
        "192.168.0.1",
        "24",
        "192.168.0.1"
    ]

    configurations = [
        "IPV4 router address (192.168.0.1): ",
        "desired subnet (24): ",
        "IPV4 router dns (192.168.0.1): "
    ]

    # Use existing values as defaults when present
    existing = {
        'router': config.get('router') or config.get('address'),
        'subnet': config.get('subnet'),
        'dns': config.get('dns')
    }

    # Write updated config using same validation as init.py
    with open('.config', 'w') as f:
        for i, prompt in enumerate(configurations):
            # Get current value or default
            current = existing.get(entry_list[i]) or defaults[i]
            user_input = input(f"Please enter the {prompt}")
            if not user_input:
                user_input = current
            # Validate IP addresses (for router and DNS)
            elif user_input and (i == 0 or i == 2):
                # regex validation for IP address
                import re
                ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
                if not ip_pattern.match(user_input):
                    print("\nInvalid IP address format. Using default.")
                    user_input = defaults[i]
            # Validate subnet
            elif user_input and i == 1:
                # validation for subnet
                if not user_input.isdigit() or not (0 < int(user_input) <= 32):
                    print("\nInvalid subnet format. Using default.")
                    user_input = defaults[i]

            # Write to config file
            key = entry_list[i]
            config[key] = user_input
            f.write(f"{key}={user_input}\n")

    # keep canonical 'address' key for compatibility
    if 'router' in config:
        config['address'] = config['router']
