# libraries
import os, requests # requests for API calls and os for loading keys
from ipwhois import IPWhois # Used for a whois lookup
from dotenv import load_dotenv # Used to load API keys from .env file
from datetime import datetime, timezone # Used to get current date and time in UTC
from multiprocessing import Pool # Used to quickly check IP addresses from a list (run checks concurrently)
import argparse # Used for command line arguments
import re # Used to strip the output of ANSI color codes when saving output to a file

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[32m"
YELLOW = "\033[93m"
GREY = "\033[90m"
CYAN = "\033[36m"
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

# Function for whois lookup
def whois_lookup(IP):

    # Pool() messes up the formatting of the output, so instead of using print()
    # to display the info, an empty list called output is created and wherever print()
    # is usually used, output.append() is used instead.
    output = []
    
    try:
        # Make IPWhois object
        obj = IPWhois(IP)

        # Perform a WHOIS lookup
        lookup = obj.lookup_whois()
    except Exception as e:
        output.append(f"Error: {e}")

    # Append whois info to output
    output.append(f"{BOLD}-~-~- Whois -~-~-{END}")
    output.append(f" * Description: {ITALIC}{BOLD}{CYAN}{lookup.get('asn_description')}{END}")
    output.append(f" * Country Code: {lookup.get('asn_country_code')}")
    output.append(f" * ASN: {lookup.get('asn')}")
    output.append(f" * ASN Date: {lookup.get('asn_date')}")

    return "\n".join(output)

# Function for Virus Total API call and printing the reponse
def virus_total_lookup(IP):

    output = []

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
    # Appends connection error to the output if the API can't be reached
    except requests.ConnectionError:
        output.append("Connection Error")

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

    # Append formatted Virus Total reponse to output and add color
    output.append(f"{BOLD}-~-~- Virus Total -~-~-{END}")
    output.append(f" * {ITALIC}{add_color('!  Malicious ', RED)} Detections: {add_color(malicious_count, malicious_color)}/{total}")
    output.append(f" * {ITALIC}{add_color('?  Suspicious', YELLOW)} Detections: {add_color(suspicious_count, suspicious_color)}/{total}")
    output.append(f" * {ITALIC}{add_color(':) Harmless  ', GREEN)} Detections: {add_color(harmless_count, harmless_color)}/{total}")
    output.append(f" * {add_color('              Undetected', GREY)}: {undetected_count}/{total}")
    output.append(f" * Community Score: {add_color(reputation, reputation_color)}")

    return "\n".join(output)

# Function for AbuseIPDB API call and printing the reponse
def abuse_ipdb_lookup(IP):
    
    output = []

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
        # Appends connection error to the output if the API can't be reached
        output.append("Connection Error")

    # Get the abuse confidence score from the json data (ipdb_data)
    abuse_score = ipdb_data.get("data", {}).get("abuseConfidenceScore", 0)

    # Get the total number of reports from the json data (ipdb_data)
    total_reports = ipdb_data.get("data", {}).get("totalReports", 0)

    # Decide color for the abuse confidence score
    color = GREEN if abuse_score == 0 else YELLOW if abuse_score <= 50 else RED

    # Append formatted AbuseIPDB reponse to the output and add color
    output.append(f"\n{BOLD}-~-~- AbuseIPDB -~-~-{END}")
    output.append(f" * Total Reports: {BOLD}{total_reports}{END}")
    output.append(f" * Abuse Confidence Score: {add_color(f'{abuse_score}%', color)}\n")

    return "\n".join(output)


# Read in IP addresses from user provided text file and add them to a list.
# I plan on updating this to be able to remove things like commas (CSV) and other seperators
# and only read in IP addresses. Right now the file must be formatted like this:
#
#   1.1.1.1
#   8.8.8.8
#   204.76.203.30
#
def get_ip_list(filename):
    # Create list
    ips = []

    # Open file
    with open(filename, "r") as file:
        # For every line in the file
        for line in file:
            # Remove whitespaces from each line
            ip = line.strip()
            # if there is data/if an IP exists
            if ip:
                # Append the IP to the list called "ips"
                ips.append(ip)
    # Return the list
    return ips

# Run the API call functions on the IP
def check_ip(IP):
    output = []

    output.append(f"\nChecking IP address: {BOLD}{IP}{END}\n")

    # Append the output of each function to the output of check_ip
    output.append(virus_total_lookup(IP))
    output.append(abuse_ipdb_lookup(IP))
    output.append(whois_lookup(IP))

    return "\n".join(output)

# Function to remove ANSI codes from output.
# Just a disclaimer, I used AI to make this function.
def remove_color(s):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', s)

def main():
    results = []
    # Create arg parser
    parser = argparse.ArgumentParser()
    
    # Argument for IP
    parser.add_argument("input", help="IP address(es) or file containing IPs")
    # Argument for saving output to a file
    parser.add_argument("-o", "--output", help="Save output to a file")

    args = parser.parse_args()

    # If the argument ends with .txt, run the get_ip_list functions to make each line in the
    # user provided text file a part if the list called "ips"
    # I plan on updating this to take more than just text files.
    if args.input.endswith(".txt"):
        ips = get_ip_list(args.input)
        # Pool from multiprocessing is used to check each IP address concurrently/in parallel.
        # len(ips) is used to set the number of processes equal to the number of IP addresses
        # in the ips list. Limit this to a reasonable amount for your machine.
        with Pool(len(ips)) as p:
            results = p.map(check_ip, ips)

        # Print the results
        for result in results:
            print(result)
            print(f"\n{ITALIC}{RED}-~-~--~-~--~-~--~-~--~-~--~-~--~-~--~-~-{END}")
    else:
        # Since print wasn't used in check_ip, save the output as a variable named result
        # then print "result"
        results.append(check_ip(args.input))
        for result in results:
            print(result)

    # If -o or --output is provided in the command line argument
    if args.output:
        # Save args.output to variable called filename and add .txt to name if user didn't specify.
        filename = args.output if args.output.endswith(".txt") else args.output + ".txt"
        # Open/create a text file with the user specified name
        with open(filename, "w") as f:
            # For each line in the results
            for line in results:
                # Write the line to the file
                f.write(remove_color(line) + "\n\n-~-~--~-~--~-~--~-~--~-~--~-~--~-~--~-~-\n")
        print(f"\n{GREEN}Saved to file:{END} {GREY}{filename}{END}")

    # Print the date and time the report(s) were made at.
    print(f"\n{ITALIC}Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}{END}\n")

if __name__ == "__main__":
    main()
