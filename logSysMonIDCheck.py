#!/usr/bin/env python

import os
import re
import json
import sys
import csv
from xml.etree import ElementTree

# Define the chapters and their associated Sysmon event IDs
chapters = {
    "Chapter 1: Process Creation": ["1"],
    "Chapter 2: File Creation": ["11"],
    "Chapter 3: Registry Modification": ["13", "14", "12"],
    "Chapter 4: Network Connection": ["3", "4", "5", "22"],
    "Chapter 5: Driver Loading": ["6"],
    "Chapter 6: Image Loading": ["7"],
    "Chapter 7: Raw Access Read": ["10"],
    "Chapter 8: Process Termination": ["5"],
    "Chapter 9: WMI Activity": ["18", "19"],
    "Chapter 10: PowerShell Activity": ["7", "8"],
    "Chapter 11: Service Configuration Change": ["17"],
    "Chapter 12: Anomaly Detection": ["255"]
}

# Function to check Sysmon event IDs in a log file
def check_sysmon_event_ids(file_path):
    try:
        file_extension = os.path.splitext(file_path)[1].lower()

        if file_extension == ".txt" or file_extension == ".log":
            with open(file_path, "r") as log_file:
                log_data = log_file.readlines()
                results = {}
                for chapter, event_ids in chapters.items():
                    chapter_lines = []
                    for line in log_data:
                        for event_id in event_ids:
                            if re.search(fr"EventID\s*=\s*{event_id}", line):
                                chapter_lines.append(line.strip())
                    if chapter_lines:
                        results[chapter] = chapter_lines
                
                return results

        elif file_extension == ".json":
            with open(file_path, "r") as json_file:
                log_data = json.load(json_file)
                results = {}
                for chapter, event_ids in chapters.items():
                    chapter_lines = []
                    for entry in log_data:
                        for event_id in event_ids:
                            if "EventID" in entry and entry["EventID"] == event_id:
                                chapter_lines.append(entry)
                    if chapter_lines:
                        results[chapter] = chapter_lines

                return results

        elif file_extension == ".evtx":
            from xml.etree.ElementTree import ParseError

            try:
                with open(file_path, "rb") as evtx_file:
                    results = {}
                    for chapter, event_ids in chapters.items():
                        chapter_lines = []
                        try:
                            for _, elem in ElementTree.iterparse(evtx_file):
                                if elem.tag.endswith("Event"):
                                    event_id = elem.find(".//EventID").text
                                    if event_id in event_ids:
                                        chapter_lines.append(ElementTree.tostring(elem, encoding="utf-8").decode())
                                    elem.clear()
                            if chapter_lines:
                                results[chapter] = chapter_lines
                        except ParseError:
                            pass

                    return results
            except Exception as e:
                return str(e)
        
        else:
            return "Unsupported file format."

    except Exception as e:
        return str(e)

# Function to generate CSV files for each chapter
def generate_chapter_csv(results, folder_name, analyzed_filename):
    for chapter, chapter_lines in results.items():
        chapter_filename = f"{analyzed_filename}-{chapter.replace(' ', '_')}-chaptercount.csv"
        with open(os.path.join(folder_name, chapter_filename), "w", newline="") as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(["Full Log Line"])
            for line in chapter_lines:
                csv_writer.writerow([line])

# Function to generate a CSV file for event lines
def generate_event_lines_csv(results, folder_name, analyzed_filename):
    event_lines = []
    for chapter_lines in results.values():
        event_lines.extend(chapter_lines)
    
    event_filename = f"{analyzed_filename}-eventlines.csv"
    with open(os.path.join(folder_name, event_filename), "w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Full Log Line"])
        for line in event_lines:
            csv_writer.writerow([line])

# Check if a filename argument is provided
if len(sys.argv) != 2:
    print("Usage: python script_name.py log_file_path")
    sys.exit(1)

# Get the log file path from the command-line argument
log_file_path = sys.argv[1]

# Extract the analyzed filename (without extension)
analyzed_filename = os.path.splitext(os.path.basename(log_file_path))[0]

# Create a folder named "SysmonEventIDResult" to store the results
folder_name = "SysmonEventIDResult"
os.makedirs(folder_name, exist_ok=True)

# Call the function to check Sysmon event IDs in the log file
results = check_sysmon_event_ids(log_file_path)

# Generate CSV files for each chapter and event lines
generate_chapter_csv(results, folder_name, analyzed_filename)
generate_event_lines_csv(results, folder_name, analyzed_filename)

# Print a message indicating the CSV files generated
print(f"Chapter-specific CSV files and event lines CSV file generated in the '{folder_name}' folder.")
