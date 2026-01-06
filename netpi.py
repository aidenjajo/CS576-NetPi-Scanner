#!/usr/bin/env python3

"""
- Parser for command-line arguments for NetPi-Scanner
- Supports options for scanning, performance measurement, web UI launch, and configuration management
- Integrates with other modules to execute requested functionalities
"""

import argparse
import Functions.scan as scan_module
import Functions.peformance as performance_module
import WebUI.host as webui_module
import Functions.clear_cache as clear_cache_module

def parse_arguments():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='NetPi-Scanner Command-Line Interface')
    
    parser.add_argument('-s',
                        '--scan',
                        action='store_true', 
                        help='Scan the network')
    parser.add_argument('-p',
                        '--performance',
                        action='store_true',  
                        help='Measure performance of scanned devices')
    parser.add_argument('-w',
                        '--webui',
                        action='store_true',  
                        help='Launch the Web UI')
    parser.add_argument('-u', 
                        '--update-config', 
                        action='store_true',  
                        help='Update .config file')
    parser.add_argument('-c',
                        '--scan-log',
                        action='store_true',
                        help='logging for scans, quietly updates /csv/saved_devices.csv')
    parser.add_argument('-e',
                        '--perf-log',
                        action='store_true',
                        help='logging for performance metrics, quietly updates /csv/performance_log.csv'
    )
    parser.add_argument('-dd','--delete-devices',
                        action='store_true',
                        help='Delete all saved devices from /csv/saved_devices.csv'
    )
    parser.add_argument('-dp','--delete-performance',
                        action='store_true',
                        help='Delete all saved performance data from /csv/performance_log.csv'
    )

    args = parser.parse_args()
    return args

def main():
    args = parse_arguments()

    if args.update_config:
        scan_module.update_config()
        print(".config file updated.")

    if args.scan:
        scan_module.setup_config()
        addr = scan_module.config.get('address', '<address>')
        dns_addr = scan_module.config.get('dns', '<dns_server>')

        devices = scan_module.scan_network(addr, dns_addr, scan_module.config.get('subnet', '24')) 

        scan_module.save_devices(devices)
        print("Network scan completed and devices saved.")

    if args.performance:
        devices = performance_module.load_devices()
        if devices:
            performance_module.measure_performance(devices)
            performance_module.log_performance_data(devices)
            print("Performance measurement completed and data logged.")
        else:
            print("No devices found to measure performance.")

    if args.webui:
        webui_module.begin_web_ui()
        print("Web UI launched.")

    if args.perf_log:
        #make sure log file exists
        path="scheduled_logs/performance.log"
        devices = performance_module.load_devices()
        if devices:
            performance_module.measure_performance(devices)
            performance_module.log_performance_data(devices)#updates csv/performance_log.csv
        #Adding logging info regardless if devices exists or not
        performance_module.add_log(devices,path) 

    if args.scan_log:
        scan_module.setup_config()
        addr = scan_module.config.get('address', '<address>')
        dns_addr = scan_module.config.get('dns', '<dns_server>')
        devices = scan_module.scan_network(addr, dns_addr, scan_module.config.get('subnet', '24')) 
        scan_module.device_log(devices) #saves to log and runs 

    if args.delete_devices:
        clear_cache_module.clear_saved_devices()
    if args.delete_performance:
        clear_cache_module.clear_performance_log()

if __name__ == "__main__":
    main()
