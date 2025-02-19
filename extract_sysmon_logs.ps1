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
