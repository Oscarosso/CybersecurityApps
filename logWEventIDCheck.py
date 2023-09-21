#!/usr/bin/env python

import os
import re
import json
import sys
from xml.etree import ElementTree
import csv

# Define the chapters and their associated event codes
chapters = {
    "Chapter 1: Successful Logon": ["4624"],
    "Chapter 2: Logoff": ["4634"],
    "Chapter 3: Account Lockout": ["4740"],
    "Chapter 4: User Account Management": ["4720", "4722", "4725", "4726", "4738", "4741"],
    "Chapter 5: Group Membership Changes": ["4728", "4729"],
    "Chapter 6: Privilege Escalation": ["4672"],
    "Chapter 7: File and Folder Access": ["4663"],
    "Chapter 8: Security Group Changes": ["4732", "4733", "4734", "4735", "4736", "4737"],
    "Chapter 9: Account Password Changes": ["4723", "4724"],
    "Chapter 10: RDP Session Initiation": ["4624", "10"],
    "Chapter 11: Windows Firewall Events": ["5152", "5156"],
    "Chapter 12: Suspicious PowerShell Activity": ["4103"]
}

# Function to check event codes in a log file
def check_event_codes(file_path):
    try:
        file_extension = os.path.splitext(file_path)[1].lower()

        if file_extension == ".txt" or file_extension == ".log":
            with open(file_path, "r") as log_file:
                log_data = log_file.read()
                results = []

                for chapter, event_codes in chapters.items():
                    for event_code in event_codes:
                        count = len(re.findall(fr"EventCode\s*=\s*{event_code}", log_data))
                        results.append([chapter, event_code, count])
                
                return results

        elif file_extension == ".json":
            with open(file_path, "r") as json_file:
                log_data = json.load(json_file)
                results = []

                for chapter, event_codes in chapters.items():
                    for event_code in event_codes:
                        count = len([entry for entry in log_data if "EventCode" in entry and entry["EventCode"] == event_code])
                        results.append([chapter, event_code, count])

                return results

        elif file_extension == ".evtx":
            from xml.etree.ElementTree import ParseError

            try:
                with open(file_path, "rb") as evtx_file:
                    results = []
                    for chapter, event_codes in chapters.items():
                        for event_code in event_codes:
                            try:
                                count = 0
                                for _, elem in ElementTree.iterparse(evtx_file):
                                    if elem.tag.endswith("Event"):
                                        event_id = elem.find(".//EventID").text
                                        if event_id == event_code:
                                            count += 1
                                        elem.clear()
                                results.append([chapter, event_code, count])
                            except ParseError:
                                pass

                    return results
            except Exception as e:
                return str(e)
        
        else:
            return "Unsupported file format."

    except Exception as e:
        return str(e)

# Function to generate CSV file with overview of results
def generate_overview_csv(results):
    with open("overview_results.csv", "w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Chapter Name", "Event ID", "Event Count"])
        for result in results:
            csv_writer.writerow(result)

# Function to generate CSV file with unique event IDs and descriptions
def generate_unique_event_ids_csv(results):
    unique_event_ids = {}
    for result in results:
        chapter, event_id, _ = result
        if event_id not in unique_event_ids:
            unique_event_ids[event_id] = chapter

    with open("unique_event_ids.csv", "w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Event ID", "Description"])
        for event_id, description in unique_event_ids.items():
            csv_writer.writerow([event_id, description])

# Check if a filename argument is provided
if len(sys.argv) != 2:
    print("Usage: python script_name.py log_file_path")
    sys.exit(1)

# Get the log file path from the command-line argument
log_file_path = sys.argv[1]

# Call the function to check event codes in the log file
results = check_event_codes(log_file_path)

# Generate CSV files
generate_overview_csv(results)
generate_unique_event_ids_csv(results)

# Print the results
print("Overview results CSV file and Unique event IDs CSV file generated.")
