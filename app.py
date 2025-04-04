import os
import requests
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from bs4 import BeautifulSoup

app = Flask(__name__)
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls"

def get_virustotal_report(url):
    # Step 1: Get a URL scan ID
    url_id = requests.post(
        VT_URL,
        headers={
            "x-apikey": VT_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data=f"url={url}"
    ).json().get("data", {}).get("id")

    if not url_id:
        return {"status": "error", "message": "Failed to get scan ID"}

    # Step 2: Fetch analysis report
    analysis = requests.get(
        f"{VT_URL}/{url_id}",
        headers={"x-apikey": VT_API_KEY}
    ).json()

    stats = analysis.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    total = sum(stats.values())
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    return {
        "status": "complete",
        "total_engines": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "verdict": "⚠️ Risky" if malicious > 0 or suspicious > 0 else "✅ Safe"
    }

def get_page_title(url):
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.title.string.strip() if soup.title and soup.title.string else "No title found"
    except Exception as e:
        return f"(Error fetching title)"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check-url", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"status": "error", "message": "No URL provided"})

    result = get_virustotal_report(url)
    result["url"] = url
    
    title = get_page_title(url)
    result["page_title"] = title
    
    return jsonify(result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(debug=False, host="0.0.0.0", port=port)





