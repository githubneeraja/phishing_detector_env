import requests
import os
import time
from virustotal_python import Virustotal

API_URL = "https://api-inference.huggingface.co/models/pirocheto/phishing-url-detection"
VT_API_KEY = "8f7ec68695936e9130df3d925976d0a49abb28bef7ea674f2655e4b54f2cb79a"
URLSCAN_API_KEY = "019ad617-0c59-7209-8499-ed77f3c4d524"
URLSCAN_API_URL = "https://urlscan.io/api/v1"

def predict_phishing(url: str):
    headers = {"Authorization": f"Bearer {os.getenv('HF_API_TOKEN') or os.getenv('HF_TOKEN')}"}
    response = requests.post(API_URL, headers=headers, json={"inputs": url})
    result = response.json()
    
    if isinstance(result, list) and len(result) > 0:
        for item in result[0]:
            if item["label"].lower() == "phishing":
                return item["score"]
    
    return 0.0

def check_with_virustotal(url: str):
    vtotal = Virustotal(API_KEY=VT_API_KEY)
    
    # Submit URL for analysis
    resp = vtotal.request("urls", data={"url": url}, method="POST")
    
    # Get the analysis ID from the response
    analysis_id = resp.data["id"]
    
    # Get the analysis report
    report = vtotal.request(f"analyses/{analysis_id}")
    
    return report.data

def scan_url(url: str):
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    
    # Submit URL for scanning
    submit_data = {"url": url, "visibility": "public"}
    submit_response = requests.post(f"{URLSCAN_API_URL}/scan/", headers=headers, json=submit_data)
    submit_result = submit_response.json()
    scan_id = submit_result["uuid"]
    
    # Wait for scan to complete
    result_url = f"{URLSCAN_API_URL}/result/{scan_id}/"
    while True:
        result_response = requests.get(result_url, headers=headers)
        if result_response.status_code == 200:
            break
        time.sleep(2)
    
    result = result_response.json()
    return result

if __name__ == "__main__":
    url = "http://example.com"
    print("Phishing Probability:", predict_phishing(url))
