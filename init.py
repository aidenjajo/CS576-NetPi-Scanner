#!/usr/bin/env python3

"""
Team Members: Aiden Jajo, Diego Lopez, Manuel Jimenez, Romel Aleman
School: San Diego State University
Course: CS576-03 - Computer Networks and Distributed Systems
Project: NetPi-Scanner

Initialization script for NetPi-Scanner.
Installs required packages, configures network settings, sets up cron jobs
for automated scanning, and launches the web UI.
"""

import subprocess
from Functions.init_config import config_initialization
from WebUI.host import begin_web_ui

# subprocess call to install required packages
def package_installation():

    # We can add more packages here as needed
    packages_to_install = ['python3-nmap',
                           'python3-scapy',
                           'python3-flask']

    # Install each required package
    for pkg in packages_to_install:
        print(f"\nInstalling {pkg}...")
        subprocess.check_call(['sudo', 'apt', 'install', '-y', pkg])
        print()

# Setting cronjob in user crontab for scanning and performance functions
def cronjob_setup():
    # Make sure our script is executable, script should be in same dir 
    output = subprocess.run(["chmod","+x","./cronjob_setup.sh"], capture_output=True, text=True)
    print(output.stdout)
    print(output.stderr)
    
    # Running bash script with user input for interval
    user_input = input("Please enter the cronjob interval for NetPi(Default 30 min):")
    result = subprocess.run(["./cronjob_setup.sh", user_input],capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr)
    return

if __name__ == "__main__":
    # Step 1: Install required system packages
    package_installation()
    
    # Step 2: Initialize configuration file with network settings
    config_initialization()
    
    # Step 3: Set up automated cron jobs for scanning
    cronjob_setup()
    
    # Step 4: Launch the web UI
    begin_web_ui()
