import requests
import csv
import colorama
import re
from datetime import datetime
from colorama import Fore, Style
from dotenv import load_dotenv
from datetime import datetime
from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from fpdf import FPDF
import pandas as pd

# Load API key from .env file
load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
# Base URL for VirusTotal API
BASE_URL = "https://www.virustotal.com/api/v3"

# CSV File Path
CSV_FILE = "threat_lookup_results.csv"

# Initialize colorama for colored terminal output
colorama.init()

SYSLOG_FILE = "sysmon_ips.txt"

def generate_pdf_report(csv_file, pdf_file="Threat_Report.pdf"):
    """
    Generates a properly formatted PDF report from a CSV file.
    """
    # Ensure CSV is read with proper encoding
    df = pd.read_csv(csv_file, encoding="utf-8-sig")  # Prevents BOM issue

    pdf = FPDF(orientation='L', unit='mm', format='A4')  # Landscape mode for better fit
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", style="", size=8)

    # Define column widths (adjust as needed)
    col_widths = [35, 50, 20, 20, 20, 20, 20, 25, 25, 35]
    headers = df.columns.tolist()

    # --- Add Table Header ---
    pdf.set_fill_color(200, 200, 200)
    pdf.set_font("Arial", style="B", size=9)
    
    for i, header in enumerate(headers):
        pdf.cell(col_widths[i], 8, header.encode('latin-1', 'replace').decode('latin-1'), border=1, align="C", fill=True)
    pdf.ln()

    # --- Add Table Rows ---
    pdf.set_font("Arial", size=8)
    
    for _, row in df.iterrows():
        for i, cell in enumerate(row):
            text = str(cell) if pd.notna(cell) else "N/A"
            text = text.encode('latin-1', 'replace').decode('latin-1')  # Prevent encoding errors
            pdf.cell(col_widths[i], 8, text, border=1, align="C")
        pdf.ln()  # Move to next row

    # Save PDF
    pdf.output(pdf_file, 'F')  # Force saving in proper encoding
    print(f"✅ PDF report generated: {pdf_file}")

def format_security_score(stats):
    """Formats the security score with color-coded output and prepares CSV data."""
    output = []
    csv_data = {}

    for key, value in stats.items():
        csv_data[key] = value  # Store for CSV logging
        
        if key == "malicious" and value > 0:
            output.append(f"{Fore.RED}⚠️ Malicious: {value}{Style.RESET_ALL}")
        elif key == "harmless" and value > 0:
            output.append(f"{Fore.GREEN}✅ Harmless: {value}{Style.RESET_ALL}")
        elif key == "undetected" and value > 0:
            output.append(f"{Fore.YELLOW}🟡 Undetected: {value}{Style.RESET_ALL}")
        elif value > 0:
            output.append(f"{Fore.CYAN}🔹 {key.capitalize()}: {value}{Style.RESET_ALL}")

    return "\n".join(output), csv_data  # Return both formatted output & CSV data

def save_to_csv(input_value, vt_data=None, abuse_data=None):
    """Save results from VirusTotal and AbuseIPDB to a CSV file."""
    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, mode="a", newline="") as file:
        fieldnames = [
            "Date", "Input",
            "Malicious", "Harmless", "Undetected", "Suspicious", "Timeout",  # ✅ VirusTotal
            "Abuse Score", "Total Reports", "Last Reported"  # ✅ AbuseIPDB
        ]
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()  # ✅ Write headers if file is new

        # ✅ Ensure `abuse_data` is not None
        abuse_score = abuse_data["abuseConfidenceScore"] if abuse_data else "N/A"
        total_reports = abuse_data["totalReports"] if abuse_data else "N/A"
        last_reported = abuse_data["lastReportedAt"] if abuse_data else "N/A"

        # ✅ Ensure `vt_data` is not None
        row = {
            "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Input": input_value,
            "Malicious": vt_data.get("malicious", "N/A") if vt_data else "N/A",
            "Harmless": vt_data.get("harmless", "N/A") if vt_data else "N/A",
            "Undetected": vt_data.get("undetected", "N/A") if vt_data else "N/A",
            "Suspicious": vt_data.get("suspicious", "N/A") if vt_data else "N/A",
            "Timeout": vt_data.get("timeout", "N/A") if vt_data else "N/A",
            "Abuse Score": abuse_score,
            "Total Reports": total_reports,
            "Last Reported": last_reported,
        }

        writer.writerow(row)  # ✅ Write data to CSV
        print(f"✅ Logged results to {CSV_FILE}")


def check_virustotal(value):
    """Perform a lookup on an IP, domain, or hash using VirusTotal API"""
    headers = {"x-apikey": API_KEY}

    # Ensure domain formatting is correct
    value = value.replace("[.]", ".")  # Replace obfuscated domain format

    # Determine the API endpoint based on input type
    if value.count(".") >= 1 and not value.replace(".", "").isdigit():  # Likely a domain
        endpoint = f"/domains/{value}"
    elif value.replace(".", "").isdigit():  # Likely an IP address
        endpoint = f"/ip_addresses/{value}"
    else:  # Assume it's a file hash
        endpoint = f"/files/{value}"

    url = BASE_URL + endpoint
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        security_score = data['data']['attributes'].get('last_analysis_stats', {})

        # 🔹 Color-code VirusTotal Results
        malicious = security_score.get("malicious", 0)
        suspicious = security_score.get("suspicious", 0)
        undetected = security_score.get("undetected", 0)

        malicious_colored = f"{Fore.GREEN}{malicious}{Style.RESET_ALL}" if malicious == 0 else (
            f"{Fore.YELLOW}{malicious}{Style.RESET_ALL}" if malicious < 10 else f"{Fore.RED}{malicious}{Style.RESET_ALL}"
        )

        suspicious_colored = f"{Fore.GREEN}{suspicious}{Style.RESET_ALL}" if suspicious == 0 else (
            f"{Fore.YELLOW}{suspicious}{Style.RESET_ALL}" if suspicious < 10 else f"{Fore.RED}{suspicious}{Style.RESET_ALL}"
        )

        undetected_colored = f"{Fore.CYAN}{undetected}{Style.RESET_ALL}"

        # 🎨 Format Output
        print("\n🔍 VirusTotal Threat Report:")
        print("-" * 50)
        print(f"🔹 Input: {Fore.CYAN}{value}{Style.RESET_ALL}\n")
        print(f"⚠️ Malicious: {malicious_colored}")
        print(f"🟡 Suspicious: {suspicious_colored}")
        print(f"✅ Undetected: {undetected_colored}")
        print("-" * 50)

        # Save to CSV
        save_to_csv(value, {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected
        })

    else:
        error_message = response.json().get("error", {}).get("message", "Unknown Error")
        print(f"❌ Error: {response.status_code} - {error_message}")

    
def check_abuseipdb(ip):
    """Queries AbuseIPDB to check for reports on an IP address."""
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,  # Adjust as needed
        "verbose": "true"
    }
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()
        
        # Color-code Total Reports
        total_reports = data["data"]["totalReports"]
        if total_reports == 0:
            total_reports_colored = f"{Fore.GREEN}{total_reports}{Style.RESET_ALL}"
        elif total_reports < 10:
            total_reports_colored = f"{Fore.YELLOW}{total_reports}{Style.RESET_ALL}"
        else:
            total_reports_colored = f"{Fore.RED}{total_reports}{Style.RESET_ALL}"

        return {
            "IP": data["data"]["ipAddress"],
            "Abuse Score": data["data"]["abuseConfidenceScore"],
            "Total Reports": total_reports_colored,  # ✅ Colorized output
            "Last Reported": data["data"]["lastReportedAt"]
        }
    else:
        return {"Error": f"Failed to query AbuseIPDB - {response.status_code}"}

def query_virustotal(value):
    """Perform a lookup using VirusTotal API and format results."""
    headers = {"x-apikey": API_KEY}
    value = value.replace("[.]", ".")  # Ensure proper domain formatting

    if value.count(".") >= 1 and not value.replace(".", "").isdigit():
        endpoint = f"/domains/{value}"  # Domain
    elif value.replace(".", "").isdigit():
        endpoint = f"/ip_addresses/{value}"  # IP Address
    else:
        endpoint = f"/files/{value}"  # File Hash

    url = BASE_URL + endpoint
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        security_score = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        # 🎨 Format Output
        formatted_results = (
            f"\n📊 {Fore.CYAN}VirusTotal Results:{Style.RESET_ALL}"
            f"\n{Fore.LIGHTBLACK_EX}────────────────────────────────────────{Style.RESET_ALL}"
            f"\n🔹 {Fore.RED}{'Malicious'.ljust(12)}: {security_score.get('malicious', 0)}{Style.RESET_ALL}"
            f"\n🔹 {Fore.YELLOW}{'Suspicious'.ljust(12)}: {security_score.get('suspicious', 0)}{Style.RESET_ALL}"
            f"\n🔹 {Fore.BLUE}{'Undetected'.ljust(12)}: {security_score.get('undetected', 0)}{Style.RESET_ALL}"
            f"\n🔹 {Fore.GREEN}{'Harmless'.ljust(12)}: {security_score.get('harmless', 0)}"
            f"\n🔹 {Fore.MAGENTA}{'Timeout'.ljust(12)}: {security_score.get('timeout', 0)}{Style.RESET_ALL}"
            f"\n{Fore.LIGHTBLACK_EX}────────────────────────────────────────{Style.RESET_ALL}"
        )

        print(formatted_results)
        return security_score  # ✅ Return for CSV logging
    else:
        print(f"❌ {Fore.RED}Error: {response.status_code} - {response.json().get('error', {}).get('message', 'Unknown Error')}{Style.RESET_ALL}")
        return None  # ✅ Return None in case of failure

def query_abuseipdb(ip):
    """Perform an AbuseIPDB lookup and format results."""
    
    # ✅ Ensure the input is a valid IP address
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"  # Matches IPv4 addresses
    if not re.match(ip_pattern, ip):
        print(f"⚠️  {Fore.YELLOW}Skipping AbuseIPDB check: {ip} is not a valid IP address.{Style.RESET_ALL}")
        return None  # Skip and return nothing
    
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json().get("data", {})
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        last_reported_raw = data.get("lastReportedAt", None)

        last_reported = (
            datetime.strptime(last_reported_raw, "%Y-%m-%dT%H:%M:%S%z").strftime("%B %d, %Y at %I:%M %p %Z")
            if last_reported_raw else "Never Reported"
        )

        # 🎨 Format Output
        formatted_results = (
            f"\n📊 {Fore.CYAN}AbuseIPDB Results:{Style.RESET_ALL}"
            f"\n{Fore.LIGHTBLACK_EX}────────────────────────────────────────{Style.RESET_ALL}"
            f"\n🔹 {Fore.YELLOW}IP Address   : {ip}{Style.RESET_ALL}"
            f"\n🔹 {Fore.RED if abuse_score > 50 else Fore.GREEN}Abuse Score  : {abuse_score}{Style.RESET_ALL}"
            f"\n🔹 {Fore.RED if total_reports > 50 else Fore.GREEN}Total Reports: {total_reports}{Style.RESET_ALL}"
            f"\n🔹 {Fore.BLUE}Last Reported: {Fore.LIGHTCYAN_EX}{last_reported}{Style.RESET_ALL}"
            f"\n{Fore.LIGHTBLACK_EX}────────────────────────────────────────{Style.RESET_ALL}"
        )

        print(formatted_results)
        return {
            "abuseConfidenceScore": abuse_score,
            "totalReports": total_reports,
            "lastReportedAt": last_reported
        }  # ✅ Return for CSV logging

    elif response.status_code == 422:
        print(f"❌ {Fore.RED}Skipping AbuseIPDB check: Invalid input format for {ip}.{Style.RESET_ALL}")
        return None

    else:
        print(f"❌ {Fore.RED}Error: {response.status_code} - {response.json().get('message', 'Unknown Error')}{Style.RESET_ALL}")
        return None  # ✅ Return None in case of failure

import os

SYSLOG_FILE = "sysmon_ips.txt"  # File with extracted Sysmon logs

def main():
    sysmon_file = "C:\\ThreatLookup\\filtered_sysmon_ips.txt"
    user_inputs = []  # Ensure this is initialized properly

    if os.path.exists(sysmon_file):
        print(f"\n📂 Detected Sysmon log file: {sysmon_file}")
        with open(sysmon_file, "r") as file:
            sysmon_ips = [line.strip() for line in file if line.strip()]
        
        if sysmon_ips:
            print(f"🔍 Found {len(sysmon_ips)} extracted IPs. Processing now...")
            user_inputs.extend(sysmon_ips)  # Add Sysmon logs to input list

    print("\n🔍 Threat Lookup Tool")
    print("-----------------------------------")
    print("1️⃣  Manual Batch Processing (User Input)")
    print("2️⃣  Sysmon Threat Hunting (Live Windows Logs)")
    print("-----------------------------------")

    mode_choice = input("Enter your choice (1/2): ").strip()

    if mode_choice == "1":
        manual_batch_processing()
    elif mode_choice == "2":
        if user_inputs:  # Ensure we have extracted IPs before processing
            process_inputs(user_inputs)
        else:
            print(f"⚠️ {Fore.YELLOW}No Sysmon log data found to process!{Style.RESET_ALL}")
    else:
        print(f"❌ {Fore.RED}Invalid choice. Exiting.{Style.RESET_ALL}")
        return  # Exit early if invalid input

    # ✅ Generate PDF only if the CSV exists and has data
    csv_file = "threat_lookup_results.csv"
    if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
        generate_pdf_report(csv_file)
    else:
        print(f"⚠️ {Fore.YELLOW}No threat data found. PDF report was not generated.{Style.RESET_ALL}")

def manual_batch_processing():
    """Handles manual batch processing mode."""
    choice = input("\n📂 Would you like to input a file? (y/n): ").strip().lower()

    if choice == 'y':
        file_path = input("📂 Enter file path (e.g., input_list.txt): ").strip()
        if not os.path.exists(file_path):
            print(f"❌ {Fore.RED}Error: File not found!{Style.RESET_ALL}")
            return
        with open(file_path, 'r') as file:
            user_inputs = [line.strip() for line in file if line.strip()]
    else:
        user_inputs = input("\nEnter IPs, domains, or file hashes (comma-separated): ").strip().split(',')

    # ✅ Remove duplicates & clean up input
    user_inputs = list(set([item.strip() for item in user_inputs if item.strip()]))

    if not user_inputs:
        print(f"❌ {Fore.RED}No valid inputs detected!{Style.RESET_ALL}")
        return

    process_inputs(user_inputs)  # ✅ Process the inputs

def sysmon_threat_hunting():
    """Handles Sysmon-based threat lookup mode."""
    if os.path.exists(SYSLOG_FILE):
        print(f"📂 Loading Sysmon data from: {SYSLOG_FILE}")
        with open(SYSLOG_FILE, "r") as file:
            user_inputs = [line.strip() for line in file.readlines() if line.strip()]
        process_inputs(user_inputs)  # ✅ Process extracted Sysmon logs
    else:
        print(f"⚠️ {Fore.YELLOW}No Sysmon log file found. Please ensure Sysmon logging is enabled.{Style.RESET_ALL}")

def process_inputs(user_inputs):
    """Processes a list of inputs for VirusTotal & AbuseIPDB."""
    print("\n🔍 Select an option:")
    print("1️⃣  Check VirusTotal")
    print("2️⃣  Check AbuseIPDB")
    print("3️⃣  Check Both")
    lookup_choice = input("Enter your choice (1/2/3): ").strip()

    vt_queries = 0
    abuse_queries = 0

    for user_input in user_inputs:
        print("\n" + "-" * 50)
        print(f"🔍 Processing: {Fore.CYAN}{user_input}{Style.RESET_ALL}")

        vt_result, abuse_result = None, None

        if lookup_choice in ["1", "3"]:
            vt_queries += 1
            vt_result = query_virustotal(user_input)

        if lookup_choice in ["2", "3"] and is_valid_ip(user_input):
            abuse_queries += 1
            abuse_result = query_abuseipdb(user_input)

        save_to_csv(user_input, vt_data=vt_result, abuse_data=abuse_result)

    print("\n✅ Scan Completed:")
    print(f"🔹 Total Queries      : {len(user_inputs)}")
    print(f"🔹 VirusTotal Queries: {vt_queries}")
    print(f"🔹 AbuseIPDB Queries : {abuse_queries}")
    print(f"📂 Results saved to  : {CSV_FILE}")
    print("\n--------------------------------------------------\n")


def is_valid_ip(ip):
    """Basic function to check if the input is a valid IP address."""
    import re
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return re.match(pattern, ip)

if __name__ == "__main__":
    main()