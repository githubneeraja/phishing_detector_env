from predict import predict_phishing, check_with_virustotal, scan_url
import json

# Test URL
test_url = "https://www.google.com"

print(f"Analyzing URL: {test_url}\n")
print("=" * 50)

# Test Phishing Prediction
print("\n1. Phishing Prediction:")
try:
    phishing_score = predict_phishing(test_url)
    print(f"   Phishing Probability: {phishing_score * 100:.2f}%")
except Exception as e:
    print(f"   Error: {e}")

# Test VirusTotal (this may take a moment)
print("\n2. VirusTotal Analysis:")
try:
    vt_report = check_with_virustotal(test_url)
    if vt_report and "attributes" in vt_report:
        attrs = vt_report["attributes"]
        if "last_analysis_stats" in attrs:
            print(f"   Analysis Stats: {attrs['last_analysis_stats']}")
        if "reputation" in attrs:
            print(f"   Reputation: {attrs['reputation']}")
    print("   ✓ VirusTotal report retrieved successfully")
except Exception as e:
    print(f"   Error: {e}")

# Test URLScan.io (this may take a moment)
print("\n3. URLScan.io Analysis:")
try:
    urlscan_report = scan_url(test_url)
    if urlscan_report and "task" in urlscan_report:
        print(f"   Scan URL: {urlscan_report['task'].get('url', 'N/A')}")
    print("   ✓ URLScan.io report retrieved successfully")
except Exception as e:
    print(f"   Error: {e}")

print("\n" + "=" * 50)
print("Analysis complete! Check the Streamlit dashboard at http://localhost:8501")

