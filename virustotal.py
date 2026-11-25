import requests
import base64
import os
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_virustotal(url):
    """
    Check a URL against VirusTotal's 70+ antivirus engines.
    Returns dict with threat details.
    """
    if not VT_API_KEY:
        return {"error": "No API key found", "vt_checked": False}

    try:
        # Encode URL to base64 (VirusTotal requirement)
        url_id  = base64.urlsafe_b64encode(
                    url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(endpoint, headers=headers, timeout=10)

        if response.status_code == 200:
            data    = response.json()
            stats   = data["data"]["attributes"]["last_analysis_stats"]
            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            harmless    = stats.get("harmless", 0)
            total       = malicious + suspicious + harmless

            return {
                "vt_checked"  : True,
                "malicious"   : malicious,
                "suspicious"  : suspicious,
                "harmless"    : harmless,
                "total_engines": total,
                "vt_risk_pct" : round((malicious / max(total,1)) * 100, 1)
            }
        else:
            return {"vt_checked": False,
                    "error": f"Status {response.status_code}"}

    except Exception as e:
        return {"vt_checked": False, "error": str(e)}