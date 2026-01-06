"""
Team Members: Aiden Jajo, Diego Lopez, Manuel Jimenez, Romel Aleman
School: San Diego State University
Course: CS576-03 - Computer Networks and Distributed Systems
Project: NetPi-Scanner

Network configuration initialization for NetPi-Scanner.
Prompts user for router address, subnet, and DNS settings.
Validates inputs and writes configuration to .config file.
"""

import subprocess, re
import WebUI.host
import socket

# Initial configuration for user to add there adresses and subnet
# Defaults to most common home network configurations if not provided
def config_initialization():

    # Find current ip address for finding default router
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 80))
    ip = s.getsockname()[0]
    s.close()
    
    # Display welcome message
    print("\nWelcome to NetPi-Scanner setup!")
    print("-------------------------------\n")

    # Configuration keys for .config file
    entry_list= [
        "router",
        "subnet",
        "dns"
    ]

    # Default values based on current IP
    defaults = [
        '.'.join(ip.split('.')[:-1]) + '.1',  # default router based on current ip
        '24',
        '.'.join(ip.split('.')[:-1]) + '.1'   # default dns based on current ip
    ]

    # Configuration prompts for user input
    configurations = [
        f"IPV4 router address ({defaults[0]}): ",
        "desired subnet (24): ",
        f"IPV4 router dns ({defaults[2]}): "
    ]

    # Open file for writing configurations to config file
    # Uses regex to check if input is valid
    # If nothing provided, use default values
    # We can add more configurations if needed
    with open('.config', 'w') as f:
        
        # Loop through each configuration option
        for i, config in enumerate(configurations):
            # Get user input for current configuration
            user_input = input(f"Please enter the {config}")
            
            # Use default if no input provided
            if not user_input:
                user_input = defaults[i]
            # Validate IP address format for router and DNS
            elif user_input and (i == 0 or i == 2):
                # regex validation for IP address
                ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
                if not ip_pattern.match(user_input):
                    print("\nInvalid IP address format. Using default.")
                    user_input = defaults[i]
            # Validate subnet value
            elif user_input and i == 1:
                # validation for subnet
                if not user_input.isdigit() or not (0 < int(user_input) <= 32):
                    print("\nInvalid subnet format. Using default.")
            
            # Write configuration to file
            key = entry_list[i]
            f.write(f"{key}={user_input}\n")
            print() # new line

        # Confirm configuration saved
        print("Configuration saved to .config file.")
    return
