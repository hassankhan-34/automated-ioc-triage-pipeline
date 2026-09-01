import requests
import ipaddress
from datetime import datetime

# ==========================================
# API KEYS (HARDCODED) - REPLACE THESE!
# ==========================================

VT_API_KEY = "Enter Your VirusTotal Api Here"  # ← REPLACE WITH YOUR ACTUAL KEY
ABUSEIPDB_API_KEY = "Enter Your Abuseip Api Here"  # ← REPLACE WITH YOUR ACTUAL KEY

# ==========================================
# VALIDATE API KEYS (NEW)
# ==========================================

def validate_api_keys():
    """Check if API keys are properly set"""
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        print("[!] ERROR: Please replace VT_API_KEY with your actual VirusTotal API key")
        return False
    if ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY_HERE":
        print("[!] ERROR: Please replace ABUSEIPDB_API_KEY with your actual AbuseIPDB API key")
        return False
    return True

# ==========================================
# VALIDATE IP ADDRESS
# ==========================================

def validate_ip(ip):
    """
    Check whether the provided value is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# ==========================================
# VIRUSTOTAL IP ANALYSIS
# ==========================================

def check_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "success": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }
        else:
            error_msg = f"VirusTotal Error: {response.status_code}"
            if response.status_code == 401:
                error_msg = "❌ VirusTotal: Invalid API Key (401) - Please check your VT_API_KEY"
            return {"success": False, "error": error_msg}

    except requests.exceptions.RequestException as error:
        return {"success": False, "error": f"VirusTotal Request Error: {error}"}

# ==========================================
# ABUSEIPDB IP ANALYSIS
# ==========================================

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=15)

        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "success": True,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0)
            }
        else:
            error_msg = f"AbuseIPDB Error: {response.status_code}"
            if response.status_code == 401:
                error_msg = "❌ AbuseIPDB: Invalid API Key (401) - Please check your ABUSEIPDB_API_KEY"
            return {"success": False, "error": error_msg}

    except requests.exceptions.RequestException as error:
        return {"success": False, "error": f"AbuseIPDB Request Error: {error}"}

# ==========================================
# RISK SCORE CALCULATION
# ==========================================

def calculate_risk_score(vt_result, abuse_result):
    score = 0

    if vt_result.get("success"):
        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)
        score += min(malicious * 5, 50)
        score += min(suspicious * 2, 20)

    if abuse_result.get("success"):
        abuse_score = abuse_result.get("abuse_score", 0)
        score += abuse_score * 0.30

    return min(round(score), 100)

# ==========================================
# SEVERITY CLASSIFICATION
# ==========================================

def classify_severity(risk_score):
    if risk_score >= 80:
        return "CRITICAL"
    elif risk_score >= 60:
        return "HIGH"
    elif risk_score >= 30:
        return "MEDIUM"
    else:
        return "LOW"

# ==========================================
# SOC ANALYST TRIAGE VERDICT
# ==========================================

def get_soc_verdict(severity):
    verdicts = {
        "CRITICAL": "MALICIOUS - IMMEDIATE INVESTIGATION REQUIRED",
        "HIGH": "POTENTIALLY MALICIOUS - INVESTIGATION RECOMMENDED",
        "MEDIUM": "SUSPICIOUS - FURTHER ANALYSIS REQUIRED",
        "LOW": "LOW RISK - MONITOR"
    }
    return verdicts.get(severity, "UNKNOWN")

# ==========================================
# MAIN PROGRAM
# ==========================================

print("=== AUTOMATED IOC TRIAGE PIPELINE ===\n")

# Validate API keys first
if not validate_api_keys():
    print("\n[!] Please update the API keys in the script and try again.")
    exit()

raw_input_ips = input("\nEnter IP addresses separated by commas: ")
user_ips = [ip.strip() for ip in raw_input_ips.split(",") if ip.strip()]

if not user_ips:
    print("[!] No IP addresses provided.")
    exit()

# ==========================================
# CREATE REPORT
# ==========================================

report_content = (
    "# Automated Incident Triage Report\n\n"
    f"Generated on: {datetime.now()}\n\n"
    "## IOC Analysis Results\n\n"
)

print("\n--- Processing Entered IOCs ---\n")

# ==========================================
# ANALYZE EACH IP
# ==========================================

for ip in user_ips:
    if not validate_ip(ip):
        print(f"[!] Invalid IP skipped: {ip}")
        report_content += (
            f"## IOC: {ip}\n\n"
            "**Status:** INVALID IP ADDRESS\n\n"
            "---\n\n"
        )
        continue

    print(f"[+] Triaging IOC: {ip}")
    ioc_type = "IP Address"

    print("    [*] Checking VirusTotal...")
    vt_result = check_virustotal_ip(ip)

    print("    [*] Checking AbuseIPDB...")
    abuse_result = check_abuseipdb(ip)

    risk_score = calculate_risk_score(vt_result, abuse_result)
    severity = classify_severity(risk_score)
    verdict = get_soc_verdict(severity)

    print(f"    [+] Risk Score: {risk_score}/100")
    print(f"    [+] Severity: {severity}")
    print(f"    [+] Verdict: {verdict}\n")

    # Report content...
    report_content += (
        f"## IOC: {ip}\n\n"
        f"**IOC Type:** {ioc_type}\n\n"
        f"**Analysis Timestamp:** {datetime.now()}\n\n"
        "### VirusTotal Results\n\n"
    )

    if vt_result.get("success"):
        report_content += (
            f"- Malicious Detections: {vt_result['malicious']}\n"
            f"- Suspicious Detections: {vt_result['suspicious']}\n"
            f"- Harmless Detections: {vt_result['harmless']}\n"
            f"- Undetected: {vt_result['undetected']}\n\n"
        )
    else:
        report_content += f"- Error: {vt_result.get('error')}\n\n"

    report_content += "### AbuseIPDB Results\n\n"
    if abuse_result.get("success"):
        report_content += (
            f"- Abuse Confidence Score: {abuse_result['abuse_score']}%\n"
            f"- Total Reports: {abuse_result['total_reports']}\n\n"
        )
    else:
        report_content += f"- Error: {abuse_result.get('error')}\n\n"

    report_content += (
        "### Risk Analysis\n\n"
        f"- Risk Score: {risk_score}/100\n"
        f"- Severity: {severity}\n\n"
        "### SOC Analyst Triage Verdict\n\n"
        f"**{verdict}**\n\n"
        "---\n\n"
    )

# ==========================================
# SAVE REPORT
# ==========================================

with open("incident_report.md", "w", encoding="utf-8") as report_file:
    report_file.write(report_content)

print("\n[+] Success!")
print("[+] incident_report.md has been generated.")
