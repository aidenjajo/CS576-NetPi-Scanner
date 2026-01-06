#!/usr/bin/env bash

#==============================================================================
# Team Members: Aiden Jajo, Diego Lopez, Manuel Jimenez, Romel Aleman
# School: San Diego State University
# Course: CS576-03 - Computer Networks and Distributed Systems
# Project: NetPi-Scanner
#
# Bash script for setting up cron jobs for automated network scanning.
# Configures scheduled scanning and performance monitoring at user-specified intervals.
#==============================================================================

# Input validation
regex='^[0-9]+$'
var1=30

# Check if user provided an interval argument
if [[ -z "$1" ]]; then
	echo "Default time used: every ${var1}th min cronjob"
elif [[ $1 =~ $regex ]]; then 
	var1="$1"
else
    echo "Invalid input, default time used: every ${var1}th min"
    var1=30
fi

# Every ($var1)th minute, need to specify python
scan_frequency="*/$var1 * * * * /usr/bin/python3 ./netpi.py --scan-log" 
perf_frequency="*/$var1 * * * * /usr/bin/python3 ./netpi.py --perf-log"

# Check if crontab exists already, suppress stderr and reg. output   
if crontab -l > /dev/null 2>&1 ; then 
    # Check if cronjob exists already
    if crontab -l 2>/dev/null | grep -q "./netpi.py --scan-log"; then
    echo "cronjob already exists for $USER"
    else 
    echo "Adding cronjob to ${USER}'s crontab"
    # Thanks to stackoverflow
    (crontab -l 2>/dev/null; echo "$scan_frequency") | crontab - 
    echo "Added cronjob to ${USER}'s crontab"
    fi
else 
    echo "No crontab exists, creating new crontab for $USER"
    echo "$scan_frequency" | crontab -
fi 

# Same thing but for performance cronjob
if crontab -l > /dev/null 2>&1 ; then 
    # Check if cronjob exists already
    if crontab -l 2>/dev/null | grep -q "./netpi.py --perf-log"; then
    echo "cronjob already exists for $USER"
    else 
    echo "Adding cronjob to ${USER}'s crontab"
    # Thanks to stackoverflow
    (crontab -l 2>/dev/null; echo "$perf_frequency") | crontab - 
    echo "Added cronjob to ${USER}'s crontab"
    fi
else 
    echo "No crontab exists, creating new crontab for $USER"
    echo "$perf_frequency" | crontab -
fi 

# In case it logging dir changes later
LOG_DIR="./scheduled_logs"

# Verify the directory exists
if [ ! -d "$LOG_DIR" ]; then
    echo "$LOG_DIR does not exist, creating now"
    mkdir -p "$LOG_DIR"
fi

# Create logging files for cronjob
touch "$LOG_DIR/performance.log"
echo "${LOG_DIR}/performance.log created"

touch "$LOG_DIR/scan.log"
echo "${LOG_DIR}/scan.log created"

# Making read/write-able to all users
chmod 666 "$LOG_DIR/performance.log"
chmod 666 "$LOG_DIR/scan.log"
