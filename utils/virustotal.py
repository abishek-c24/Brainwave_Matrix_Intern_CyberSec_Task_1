import os
import base64
import requests
import validators
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_url_virustotal(url):

    if not validators.url(url):
        return "❌ Invalid URL"
    
    if not API_KEY:
        return "❌ Missing API key"

    try:
        # Encode URL for VT format
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        headers = {
            "x-apikey": API_KEY
        }

        # Fetch report
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers
        )

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                return f"🔴 Malicious ({malicious} engines)"
            elif suspicious > 0:
                return f"🟠 Suspicious ({suspicious} engines)"
            else:
                return "✅ Clean"
        else:
            return f"⚠️ VT API Error ({response.status_code})"
    except Exception as e:
        return f"⚠️ VT error: {str(e)}"
