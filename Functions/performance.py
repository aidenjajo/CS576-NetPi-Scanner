#!/usr/bin/env python3

"""
Team Members: Aiden Jajo, Diego Lopez, Manuel Jimenez, Romel Aleman
School: San Diego State University
Course: CS576-03 - Computer Networks and Distributed Systems
Project: NetPi-Scanner

Performance measurement utilities for network devices.
Measures ICMP ping response times, TCP connection times, bandwidth,
and performs port scanning. Logs results to CSV files.
"""

from scapy.all import sr1, IP, ICMP, TCP
import os
import time
import csv
import socket
import statistics

def load_devices(filename='CSV/saved_devices.csv'):
    """Load saved devices from CSV file."""
    devices = []
    try:
        # Open and read CSV file
        with open(filename, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                devices.append(row)
    except FileNotFoundError:
        print(f"File {filename} not found. No devices to load.")
    return devices


# global verbosity flag (default False)
VERBOSE = False

def log_performance_data(devices, filename='CSV/performance_log.csv'):
    """Log performance data to a CSV file"""
    # if CSV directory does not exist, create it
    dirname = os.path.dirname(filename)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname, exist_ok=True)

    # Write performance data to CSV
    with open(filename, 'w', newline='') as f:
        # Define CSV column headers
        fieldnames = [
            'IP',
            'icmp_sent', 'icmp_received', 'icmp_loss_pct', 'rtt_avg',
            'tcp_port', 'tcp_connect',
            'bandwidth_kbps', 'open_ports'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        # Write each device's performance metrics
        for device in devices:
            ip = device['IP']
            writer.writerow({
                'IP': ip,
                'icmp_sent': device.get('icmp_sent', ''),
                'icmp_received': device.get('icmp_received', ''),
                'icmp_loss_pct': device.get('icmp_loss_pct', ''),
                'rtt_avg': device.get('rtt_avg', ''),
                'tcp_port': device.get('tcp_port', ''),
                'tcp_connect': device.get('tcp_connect', ''),
                'bandwidth_kbps': device.get('bandwidth_kbps', ''),
                'open_ports': device.get('open_ports', '')
                
            })

def measure_performance(devices):
    """Measure performance metrics for each device"""
    total = len(devices)
    # Loop through each device and measure performance
    for i, device in enumerate(devices):
        devices[i] = measure_device(device, i, total)
    return devices


def measure_device(device, i, total):
    """Measure performance metrics for a single device"""
    ip = device['IP']
    # Progress: quiet mode shows only the IP; verbose shows index and label
    if VERBOSE:
        print(f"[{i+1}/{total}] Working on {ip}", flush=True)
    else:
        print(f"{ip}", flush=True)

    # ICMP ping measurements (uses scapy)
    icmp_results = perform_icmp_pings(ip, count=4, timeout=2)
    device.update(icmp_results)
    sent = icmp_results.get('icmp_sent', 0)
    loss = icmp_results.get('icmp_loss_pct')
    avg = icmp_results.get('rtt_avg')

    # Scan for open ports
    open_ports = scan_ports(ip)
    device['open_ports'] = ','.join(map(str, open_ports)) if open_ports else 'None'
    if VERBOSE:
        print(f"  Open ports: {device['open_ports']}")

    # Display ICMP results if verbose
    if VERBOSE:
        if sent == 0:
            print(f"  ICMP: no-icmp")
        else:
            print(f"  ICMP: loss={loss}%, avg={avg}ms")

    # TCP connect timing (only port 80)
    tcp_time = tcp_connect_time(ip, 80, timeout=2)
    device['tcp_port'] = 80 if tcp_time is not None else None
    device['tcp_connect'] = tcp_time
    if VERBOSE:
        if tcp_time is None:
            print(f"  TCP 80: closed/timeout")
        else:
            print(f"  TCP 80: {tcp_time} ms")

    # bandwidth measurement (only if tcp connect succeeded)
    bandwidth = None
    if tcp_time is not None:
        bandwidth = measure_bandwidth_for_device(ip, 80)
    device['bandwidth_kbps'] = bandwidth
    if VERBOSE:
        print(f"  bandwidth_kbps: {bandwidth}")

    return device


def print_performance_summary(devices):
    """Print a summary table of performance metrics"""
    print("Performance Summary:")
    print(f"{ 'IP':<15} {'loss%':<7} {'rtt_avg':<10} {'bandwidth_kbps':<15} {'tcp_port':<8} {'tcp':<8}")
    for device in devices:
        ip = device['IP']
        loss = device.get('icmp_loss_pct', 'N/A')
        rtt_avg = device.get('rtt_avg', 'N/A')
        bandwidth = device.get('bandwidth_kbps', 'N/A')
        tcp_port = device.get('tcp_port', 'N/A')
        tcp = device.get('tcp_connect', 'N/A')
        print(f"{ip:<15} {loss!s:<7} {rtt_avg!s:<10} {str(bandwidth):<15} {str(tcp_port):<8} {str(tcp):<8}")


def perform_icmp_pings(ip, count=4, timeout=2):
    """Perform ICMP ping tests and calculate statistics"""
    sent = 0
    rtts = []
    
    # Send multiple ping packets
    for i in range(count):
        try:
            sent += 1
            start = time.monotonic()
            # Send ICMP echo request
            reply = sr1(IP(dst=ip)/ICMP(), timeout=timeout, verbose=False)
            if reply is not None:
                # Calculate round-trip time
                elapsed = (time.monotonic() - start) * 1000.0
                rtts.append(elapsed)
        except Exception as e:
            # timeout, permission error, or other network error; log and continue (verbose only)
            if VERBOSE:
                print(f"ICMP error for {ip}: {e}", flush=True)
            continue

    # Calculate packet loss and average RTT
    received = len(rtts)
    loss_pct = round(((sent - received) / sent) * 100, 1) if sent > 0 else 100.0
    if rtts:
        rtt_avg = round(statistics.mean(rtts), 1)
    else:
        rtt_avg = None

    return {
        'icmp_sent': sent,
        'icmp_received': received,
        'icmp_loss_pct': loss_pct,
        'rtt_avg': rtt_avg
    }


def tcp_connect_time(ip, port, timeout=2):
    """Measure TCP connection time to a specific port"""
    try:
        # Create TCP socket and attempt connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            start = time.monotonic()
            sock.connect((ip, port))
            elapsed = (time.monotonic() - start) * 1000.0
        return round(elapsed, 1)
    except Exception:
        return None

def measure_bandwidth_for_device(ip, port, timeout=5, max_bytes=65536):
    """Measure bandwidth by downloading data from HTTP server"""
    try:
        # Create HTTP GET request
        req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            send_start = time.monotonic()
            s.sendall(req)

            # Read response data
            total = 0
            s.settimeout(timeout)
            while total < max_bytes:
                try:
                    chunk = s.recv(4096)
                except Exception:
                    break
                if not chunk:
                    break
                total += len(chunk)
            read_end = time.monotonic()

        # Calculate bandwidth in kbps
        elapsed = read_end - send_start
        if elapsed <= 0 or total == 0:
            return None
        kbps = (total * 8) / (elapsed * 1000.0)
        return round(kbps, 1)
    except Exception:
        return None


def scan_ports(ip) -> list[int]:
    """Scan common ports to check which are open"""
    # List of common ports to scan
    port_list = [22, 80, 433, 20, 21, 8080]    
    open_ports = []
    
    # Scan each port using SYN scan
    for port in port_list:
        # Create SYN packet
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        
        # Send and wait for response
        resp = sr1(pkt, timeout=1, verbose=False)
        
        # Check for SYN-ACK (open port)
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN-ACK (SA flags)
                open_ports.append(port)
                # Send RST to close connection
                rst = IP(dst=ip) / TCP(dport=port, flags="R")
                sr1(rst, timeout=1, verbose=False)
    
    return sorted(open_ports)

if __name__ == "__main__":
    # VERBOSE is a module-level constant (default False).
    # Load devices from CSV
    devices = load_devices()
    if not devices:
        print("No devices found to measure performance.")
    else:
        # Measure performance for all devices
        devices = measure_performance(devices)
        # Print summary table
        print_performance_summary(devices)
        # Log results to CSV
        log_performance_data(devices)
        print("Performance data logged to CSV/performance_log.csv")
