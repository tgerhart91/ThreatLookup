ThreatLookup
ThreatLookup is an automated threat intelligence and network monitoring tool that queries VirusTotal and AbuseIPDB to analyze IP addresses, domains, and file hashes for potential threats.

It integrates with Windows Sysmon logs to extract network connections and identify suspicious activity, offering batch processing, CSV logging, and PDF report generation for efficient security analysis.

Features
✅ Query VirusTotal and AbuseIPDB for real-time threat intelligence
✅ Batch process user-defined lists or live Sysmon logs
✅ Filter known safe IPs before querying APIs to optimize requests
✅ Save results to CSV for further analysis
✅ Generate PDF reports for documentation and reporting
✅ Color-coded outputs for better readability

Installation
1. Clone the Repository
sh
Copy
Edit
git clone https://github.com/tgerhart91/ThreatLookup.git
cd ThreatLookup
2. Install Dependencies
Ensure you have Python 3.8+ installed, then install the required dependencies:

sh
Copy
Edit
pip install -r requirements.txt
3. Configure API Keys
You'll need API keys for VirusTotal and AbuseIPDB:

Get a VirusTotal API key
Get an AbuseIPDB API key
Create a .env file in the project folder and add your API keys:

sh
Copy
Edit
VIRUSTOTAL_API_KEY=your_virustotal_api_key  
ABUSEIPDB_API_KEY=your_abuseipdb_api_key  
Usage
Option 1: Manual Batch Processing
Run the script and manually input IP addresses, domains, or file hashes:

sh
Copy
Edit
python threat-lookup.py
Choose Manual Batch Processing
Enter a comma-separated list of IPs/domains/hashes
Select a lookup option (VirusTotal, AbuseIPDB, or both)
Option 2: Automated Sysmon Threat Hunting
To monitor active network connections, ensure Sysmon is installed and configured.

1. Install Sysmon
Download Sysmon from Sysinternals and install it:

sh
Copy
Edit
sysmon -accepteula -i sysmon-config.xml
2. Run ThreatLookup
sh
Copy
Edit
python threat-lookup.py
Choose Sysmon Threat Hunting
The script will extract live network logs and analyze them
Results are saved in threat_lookup_results.csv and Threat_Report.pdf
Output Files
📂 threat_lookup_results.csv → Stores lookup results in CSV format
📂 Threat_Report.pdf → Generates a PDF summary of threat intelligence

Example Output
Terminal Output
yaml
Copy
Edit
🔍 Processing: 8.8.8.8

📊 VirusTotal Results:
────────────────────────────────────────
🔹 Malicious   : 0
🔹 Suspicious  : 0
🔹 Undetected  : 31
🔹 Harmless    : 63
🔹 Timeout     : 0
────────────────────────────────────────

📊 AbuseIPDB Results:
────────────────────────────────────────
🔹 IP Address   : 8.8.8.8
🔹 Abuse Score  : 0
🔹 Total Reports: 210
🔹 Last Reported: February 18, 2025 at 04:04 PM UTC
────────────────────────────────────────
✅ Logged results to threat_lookup_results.csv
PDF Report Output
The Threat Report PDF includes all scanned entries with threat intelligence results, formatted for easy review.
