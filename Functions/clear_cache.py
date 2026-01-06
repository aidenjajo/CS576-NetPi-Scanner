"""
Team Members: Aiden Jajo, Diego Lopez, Manuel Jimenez, Romel Aleman
School: San Diego State University
Course: CS576-03 - Computer Networks and Distributed Systems
Project: NetPi-Scanner

File deletion utilities for clearing cached device and performance data.
Provides functions to clear CSV files with user confirmation prompts
to prevent accidental data loss.
"""

import os

def clear_saved_devices(filename='CSV/saved_devices.csv'):
    """Clear the saved devices CSV file after user confirmation."""
    # Check if file exists before attempting deletion
    if os.path.exists(filename):
        # Prompt user for confirmation
        confirm = input(f"Are you sure you want to delete '{filename}'? (y/n): ")
        if confirm.lower() == 'y':
            # Delete the file
            os.remove(filename)
            print(f"Deleted '{filename}'.")
        else:
            # User cancelled operation
            print("Operation cancelled.")
    else:
        # File doesn't exist
        print(f"No saved devices file found at '{filename}'.")

def clear_performance_log(filename='CSV/performance_log.csv'):
    """Clear the performance log CSV file after user confirmation."""
    # Check if file exists before attempting deletion
    if os.path.exists(filename):
        # Prompt user for confirmation
        confirm = input(f"Are you sure you want to delete '{filename}'? (y/n): ")
        if confirm.lower() == 'y':
            # Delete the file
            os.remove(filename)
            print(f"Deleted '{filename}'.")
        else:
            # User cancelled operation
            print("Operation cancelled.")
    else:
        # File doesn't exist
        print(f"No performance log file found at '{filename}'.")
