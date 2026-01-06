#!/usr/bin/env python3

"""
Team Members: Aiden Jajo, Diego Lopez, Manuel Jimenez, Romel Aleman
School: San Diego State University
Course: CS576-03 - Computer Networks and Distributed Systems
Project: NetPi-Scanner

Command-line interface parser for NetPi-Scanner.
Supports options for scanning, performance measurement, web UI launch, 
configuration management, and cache clearing.
"""

import argparse
import Functions.scan as scan_module
import Functions.peformance as performance_module
import WebUI.host as webui_module
import Functions.clear_cache as clear_cache_module

def parse_arguments():
    """Parse command line arguments for NetPi-Scanner functionality."""
    # Create argument parser with description
    parser = argparse.ArgumentParser(description='NetPi-Scanner Command-Line Interface')
    
    # Add argument for network scanning
    parser.add_argument('-s',
                        '--scan',
                        action='store_true', 
                        help='Scan the network')
    
    # Add argument for performance testing
    parser.add_argument('-p',
                        '--performance',
                        action='store_true',  
                        help='Measure performance of scanned devices')
    
    # Add argument for launching web UI
    parser.add_argument('-w',
                        '--webui',
                        action='store_true',  
                        help='Launch the Web UI')
    
    # Add argument for updating configuration
    parser.add_argument('-u', 
                        '--update-config', 
                        action='store_true',  
                        help='Update .config file')
    
    # Add argument for scan logging (used by cron jobs)
    parser.add_argument('-c',
                        '--scan-log',
                        action='store_true',
                        help='logging for scans, quietly updates /csv/saved_devices.csv')
    
    # Add argument for performance logging (used by cron jobs)
    parser.add_argument('-e',
                        '--perf-log',
                        action='store_true',
                        help='logging for performance metrics, quietly updates /csv/performance_log.csv'
    )
    
    # Add argument for deleting saved devices
    parser.add_argument('-dd','--delete-devices',
                        action='store_true',
                        help='Delete all saved devices from /csv/saved_devices.csv'
    )
    
    # Add argument for deleting performance data
    parser.add_argument('-dp','--delete-performance',
                        action='store_true',
                        help='Delete all saved performance data from /csv/performance_log.csv'
    )

    # Parse and return arguments
    args = parser.parse_args()
    return args

def main():
    """Main execution function that handles all command-line arguments."""
    # Parse command-line arguments
    args = parse_arguments()

    # Handle configuration update request
    if args.update_config:
        scan_module.update_config()
        print(".config file updated.")

    # Handle network scan request
    if args.scan:
        # Load configuration settings
        scan_module.setup_config()
        addr = scan_module.config.get('address', '<address>')
        dns_addr = scan_module.config.get('dns', '<dns_server>')

        # Perform network scan
        devices = scan_module.scan_network(addr, dns_addr, scan_module.config.get('subnet', '24')) 

        # Save discovered devices to CSV
        scan_module.save_devices(devices)
        print("Network scan completed and devices saved.")

    # Handle performance measurement request
    if args.performance:
        # Load saved devices from CSV
        devices = performance_module.load_devices()
        if devices:
            # Measure performance metrics for each device
            performance_module.measure_performance(devices)
            # Log results to CSV
            performance_module.log_performance_data(devices)
            print("Performance measurement completed and data logged.")
        else:
            print("No devices found to measure performance.")

    # Handle web UI launch request
    if args.webui:
        webui_module.begin_web_ui()
        print("Web UI launched.")

    # Handle performance logging (for cron jobs)
    if args.perf_log:
        # Make sure log file exists
        path="scheduled_logs/performance.log"
        # Load saved devices
        devices = performance_module.load_devices()
        if devices:
            # Measure performance
            performance_module.measure_performance(devices)
            # Update CSV with performance data
            performance_module.log_performance_data(devices)#updates csv/performance_log.csv
        # Adding logging info regardless if devices exists or not
        performance_module.add_log(devices,path) 

    # Handle scan logging (for cron jobs)
    if args.scan_log:
        # Load configuration
        scan_module.setup_config()
        addr = scan_module.config.get('address', '<address>')
        dns_addr = scan_module.config.get('dns', '<dns_server>')
        # Perform scan
        devices = scan_module.scan_network(addr, dns_addr, scan_module.config.get('subnet', '24')) 
        # Save to log and update CSV
        scan_module.device_log(devices) #saves to log and runs 

    # Handle device cache deletion
    if args.delete_devices:
        clear_cache_module.clear_saved_devices()
    
    # Handle performance cache deletion
    if args.delete_performance:
        clear_cache_module.clear_performance_log()

if __name__ == "__main__":
    main()
