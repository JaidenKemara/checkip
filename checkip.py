#!/usr/bin/env python3

# libraries
# sys for command line argument
# os and dotenv for loading in API keys
# requests for API calls
# datetime to get current date and time in UTC
import sys, os, requests
from dotenv import load_dotenv
from datetime import datetime, timezone

# ANSI color codes
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
GREY = "\033[90m"
BOLD = "\033[1m"
ITALIC = "\x1B[3m"
END = "\033[0m"

# Get API keys
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
IPDB_API_KEY = os.getenv("IPDB_API_KEY")

# Function to add color to text 
def add_color(text, color):
    # Returns the provided string with added the color codes
    return f"{BOLD}{color}{text}{END}"

# Function for Virus Total API call and printing the reponse
def virus_total_lookup(IP):
    # Virus Total API url
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{IP}"

    # Headers, pulling Virus Total API key from config.py
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
        }

    # Try API connection
    try:
        # Save reponse as variable named vt_data
        vt_data = requests.get(url, headers = headers).json()
    # Prints connection error if the API can't be reached
    except requests.ConnectionError:
        print("Connection Error")

    # Get the analysis stats from the json data (vt_data)
    analysis_stats = (
        vt_data.get("data", {})
               .get("attributes", {})
               .get("last_analysis_stats", {})
        ) 

    # Get the community score from the json data (vt_data)
    reputation = (
        vt_data.get("data", {})
               .get("attributes", {})
               .get("reputation", {})
        )

    # Get the number of malicious detections
    malicious_count = analysis_stats.get("malicious", 0)

    # Get the number of suspicious detections
    suspicious_count = analysis_stats.get("suspicious", 0)

    # Get the undetected count
    undetected_count = analysis_stats.get("undetected", 0)

    # Get the number of harmless detections
    harmless_count = analysis_stats.get("harmless", 0)

    # Total number of vendors
    total = harmless_count + undetected_count + suspicious_count + malicious_count

    # Decide color for each count
    # If the number of malicious detections is greater than 0, the color is set to red. Otherwise it's set to green
    malicious_color = RED if malicious_count > 0 else GREEN

    # If the number of suspicious connections is greater than 0, set the color to yellow. Otherwise it's set to green
    suspicious_color = YELLOW if suspicious_count > 0 else GREEN if malicious_count == 0 else ""

    # If the IP has a positive community score/reputation the color of the number of harmless detections is green, otherwise it has no color
    harmless_color = GREEN if malicious_count <= 0 else ""

    # If the reputation is greater than 0, color is set to green. If its less than 0, its set to red. If the reputation is 0, it has no color
    reputation_color = GREEN if reputation > 0 else RED if reputation < 0 else ""

    # Print formatted Virus Total reponse and add color
    print(f"{BOLD}-~-~- Virus Total -~-~-{END}")
    print(f" * {ITALIC}{add_color('!  Malicious ', RED)} Detections: {add_color(malicious_count, malicious_color)}/{total}")
    print(f" * {ITALIC}{add_color('?  Suspicious', YELLOW)} Detections: {add_color(suspicious_count, suspicious_color)}/{total}")
    print(f" * {ITALIC}{add_color(':) Harmless  ', GREEN)} Detections: {add_color(harmless_count, harmless_color)}/{total}")
    print(f" * {add_color('              Undetected', GREY)}: {undetected_count}/{total}")
    print(f" * Community Score: {add_color(reputation, reputation_color)}") 

# Function for AbuseIPDB API call and printing the reponse
def abuse_ipdb_lookup(IP):
    # AbuseIPDB API url
    url = "https://api.abuseipdb.com/api/v2/check"

    # API parameters 
    params = {
        # settting ipAddress parameter to the IP address provided in the function call/command line argument
        "ipAddress": IP,
        
        # Gets stats from the last 90 days
        "maxAgeInDays": 90
    }

    # Headers, pulling AbseIPDB API key from config.py
    headers = {
        "Accept": "application/json",
        "Key": IPDB_API_KEY
    }

    # Try API connection
    try:
        # Save API reponse as variable named ipdb_data
        ipdb_data = requests.get(url, headers=headers, params=params).json()

    except requests.ConnectionError:
        # Prints connection error if the API can't be reached
        print("Connection Error")

    # Get the abuse confidence score from the json data (ipdb_data)
    abuse_score = ipdb_data.get("data", {}).get("abuseConfidenceScore", 0)

    # Get the total number of reports from the json data (ipdb_data)
    total_reports = ipdb_data.get("data", {}).get("totalReports", 0)

    # Decide color for the abuse confidence score
    color = GREEN if abuse_score == 0 else YELLOW if abuse_score <= 50 else RED

    # Print formatted AbuseIPDB reponse and add color
    print(f"\n{BOLD}-~-~- AbuseIPDB -~-~-{END}")
    print(f" * Total Reports: {BOLD}{total_reports}{END}")
    print(f" * Abuse Confidence Score: {add_color(f'{abuse_score}%', color)}\n")

def main():
    # Set IP variable to the user input
    if len(sys.argv) > 1:
        IP = sys.argv[1]
        print(f"\nChecking IP address: {BOLD}{IP}{END}\n")
        # Run the API call functions with the IP variable
        virus_total_lookup(IP)
        abuse_ipdb_lookup(IP)
        print(f"{ITALIC}Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}{END}\n")

if __name__ == "__main__":
    main()