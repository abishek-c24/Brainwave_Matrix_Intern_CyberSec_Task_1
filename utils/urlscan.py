import os
import time
import requests
import validators
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("URLSCAN_API_KEY")

def get_result_with_retry(uuid, headers):
    for attempt in range(2):
        result = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/", headers=headers)
        if result.status_code == 200:
            return result.json()
        time.sleep(5)
    return None

def scan_url_with_urlscan(url):
    if not API_KEY:
        return {"status": "❌ Missing API key"}

    if not validators.url(url):
        return {"status": "❌ Invalid URL format"}

    headers = {
        "API-Key": API_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "url": url,
        "visibility": "public"
    }

    try:

        submit_resp = requests.post("https://urlscan.io/api/v1/scan/", json=payload, headers=headers)
        
        if submit_resp.status_code == 400:
            return {"status": "❌ Submit Error (400) — Possibly blocked or invalid domain"}

        if submit_resp.status_code != 200:
            return {"status": f"❌ Submit Error ({submit_resp.status_code})"}

        uuid = submit_resp.json().get("uuid")

        time.sleep(8)

        result_json = get_result_with_retry(uuid, headers)

        if result_json:
            domain = result_json.get("page", {}).get("domain", "N/A")
            verdict = result_json.get("verdicts", {}).get("overall", {}).get("score", 0)

            if verdict >= 5:
                status = f"🔴 Malicious domain: {domain}"
            elif verdict > 0:
                status = f"🟠 Suspicious domain: {domain}"
            else:
                status = f"✅ Domain clean: {domain}"

            return {
                "status": status,
                "domain": domain,
                "verdict_score": verdict
            }
        else:
            return {"status": "⚠️ Fetch Error (404) — Retried & failed"}


    except Exception as e:
        return {"status": f"⚠️ URLScan Error: {str(e)}"}
