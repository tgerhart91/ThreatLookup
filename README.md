# ThreatLookup  
ThreatLookup is an automated threat intelligence and network monitoring tool that queries VirusTotal and AbuseIPDB to analyze IP addresses, domains, and file hashes for potential threats.  

It integrates with Windows Sysmon logs to extract network connections and identify suspicious activity, offering batch processing, CSV logging, and PDF report generation for efficient security analysis.  

## Features
- Query VirusTotal and AbuseIPDB for real-time threat intelligence  
- Batch process user-defined lists or live Sysmon logs  
- Filter known safe IPs before querying APIs to optimize requests  
- Save results to CSV for further analysis  
- Generate PDF reports for documentation and reporting  
- Color-coded outputs for better readability  

## Installation  
1. Clone the Repository  
```sh
git clone https://github.com/tgerhart91/ThreatLookup.git
cd ThreatLookup
```

2. Install Dependencies  
- Ensure you have Python 3.8+ installed, then install the required dependencies:  

```sh
pip install -r requirements.txt
```

3. Configure API Keys  
- You'll need API keys for VirusTotal and AbuseIPDB:  
- Get a VirusTotal API key  
- Get an AbuseIPDB API key  

Create a .env file in the project folder and add your API keys:  

```sh
VIRUSTOTAL_API_KEY=your_virustotal_api_key  
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
``` 
## Usage  
**Option 1:** Manual Batch Processing  
- Run the script and manually input IP addresses, domains, or file hashes:  

```sh
python threat-lookup.py
```
Choose Manual Batch Processing  
- Enter a comma-separated list of IPs/domains/hashes  
- Select a lookup option (VirusTotal, AbuseIPDB, or both)
  
**Option 2:** Automated Sysmon Threat Hunting  
- To monitor active network connections, ensure Sysmon is installed and configured.  

1. Install Sysmon  
- Download Sysmon from Sysinternals and install it:  

```sh
sysmon -accepteula -i sysmon-config.xml
```
2. Extract Network Logs Automatically  
- To extract destination IPs from Sysmon logs, schedule the PowerShell extraction script to run periodically.  

Example PowerShell Script (extract_sysmon_logs.ps1):  
```sh
# Define known safe IPs to exclude
$safeIPs = @(
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",  # Google & Cloudflare DNS
    "23.200.0.0/13", "104.64.0.0/10",            # Akamai CDN
    "13.107.0.0/16", "20.190.128.0/18",          # Microsoft O365
    "52.0.0.0/8", "54.0.0.0/8", "99.0.0.0/8",    # AWS IP Ranges (General)
    "35.192.0.0/12", "34.80.0.0/12",             # GCP
    "40.74.0.0/16", "13.64.0.0/11",              # Azure
    "185.220.101.8"                              # Known Tor Exit Node (for testing)
)

# Function to check if an IP is in a safe range
function Test-SafeIP {
    param ($ip)
    foreach ($safe in $safeIPs) {
        if ($ip -match $safe) { return $true }
    }
    return $false
}

# Get Sysmon Event ID 3 (Network Connections)
$sysmonLogs = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 3}

# Extract unique Destination IPs
$filteredIPs = $sysmonLogs | ForEach-Object {
    $eventXml = [xml]$_.ToXml()
    $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq "DestinationIp" } | Select-Object -ExpandProperty "#text"
} | Where-Object { -not (Test-SafeIP $_) } | Sort-Object -Unique

# Save to file for batch processing
$filteredIPs | Out-File -Encoding utf8 "C:\ThreatLookup\filtered_sysmon_ips.txt"

Write-Output "Extracted $($filteredIPs.Count) unique **filtered** IPs from Sysmon logs."
Write-Output "Saved to C:\ThreatLookup\filtered_sysmon_ips.txt"
```

```sh
python threat-lookup.py
```
3. Automate Extraction with Task Scheduler  
- To ensure fresh Sysmon logs are available, schedule the PowerShell script to run periodically.  

Steps to Schedule with Task Scheduler:  
- Open Task Scheduler (taskschd.msc)  
- Create a new task  
- Set Trigger → Run every X minutes/hours  
- Set Action → Start a program → powershell.exe  
- Arguments →  
```sh
-ExecutionPolicy Bypass -File "C:\ThreatLookup\extract_sysmon_logs.ps1"
```
Save & Run Task

4. Run ThreatLookup with Sysmon Data  
- Once logs are available, run ThreatLookup:

```sh
python threat-lookup.py
```

Choose Sysmon Threat Hunting  
- The script will load filtered_sysmon_ips.txt and check them against VirusTotal and AbuseIPDB.  
- Results are stored in threat_lookup_results.csv and Threat_Report.pdf  

Output Files  
- 📂 threat_lookup_results.csv → Stores lookup results in CSV format  
- 📂 Threat_Report.pdf → Generates a PDF summary of threat intelligence  

Example Output
```sh
Terminal Output
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
```
PDF Report Output  
- The Threat Report PDF includes all scanned entries with threat intelligence results, formatted for easy review.
