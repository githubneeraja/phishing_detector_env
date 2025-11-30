import streamlit as st
import json
from predict import predict_phishing, check_with_virustotal, scan_url

st.set_page_config(page_title="URL Security Analysis Dashboard", page_icon="🔒", layout="wide")

st.title("🔒 URL Security Analysis Dashboard")
st.markdown("Analyze URLs for phishing threats, VirusTotal reports, and URLScan.io analysis")

# URL input form
with st.form("url_analysis_form"):
    url_input = st.text_input("Enter URL to analyze", placeholder="https://example.com")
    submit_button = st.form_submit_button("Analyze URL", use_container_width=True)

if submit_button and url_input:
    if not url_input.startswith(("http://", "https://")):
        st.warning("⚠️ Please enter a valid URL starting with http:// or https://")
    else:
        # Create tabs for different sections
        tab1, tab2, tab3 = st.tabs(["📊 Phishing Prediction", "🛡️ VirusTotal Report", "🔍 URLScan.io Report"])
        
        # Phishing Prediction Tab
        with tab1:
            st.subheader("Phishing Detection Probability")
            with st.spinner("Analyzing URL with Hugging Face model..."):
                try:
                    phishing_score = predict_phishing(url_input)
                    probability = phishing_score * 100
                    
                    # Display probability with color coding
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.metric("Phishing Probability", f"{probability:.2f}%")
                    
                    with col2:
                        if probability >= 70:
                            st.error("🚨 High Risk")
                        elif probability >= 40:
                            st.warning("⚠️ Medium Risk")
                        else:
                            st.success("✅ Low Risk")
                    
                    # Progress bar
                    st.progress(probability / 100)
                    
                except Exception as e:
                    st.error(f"Error analyzing URL: {str(e)}")
        
        # VirusTotal Report Tab
        with tab2:
            st.subheader("VirusTotal Analysis Report")
            with st.spinner("Fetching VirusTotal report (this may take a moment)..."):
                try:
                    vt_report = check_with_virustotal(url_input)
                    
                    # Display key information
                    if vt_report:
                        # Attributes section
                        if "attributes" in vt_report:
                            attrs = vt_report["attributes"]
                            
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                if "stats" in attrs:
                                    stats = attrs["stats"]
                                    st.markdown("### 📈 Statistics")
                                    st.json(stats)
                                
                                if "last_analysis_stats" in attrs:
                                    st.markdown("### 🔍 Last Analysis Stats")
                                    st.json(attrs["last_analysis_stats"])
                            
                            with col2:
                                if "reputation" in attrs:
                                    st.markdown("### ⭐ Reputation")
                                    st.metric("Reputation Score", attrs["reputation"])
                                
                                if "last_analysis_date" in attrs:
                                    from datetime import datetime
                                    date = datetime.fromtimestamp(attrs["last_analysis_date"])
                                    st.markdown("### 📅 Last Analysis")
                                    st.write(date.strftime("%Y-%m-%d %H:%M:%S"))
                        
                        # Full report in expander
                        with st.expander("📄 View Full VirusTotal Report"):
                            st.json(vt_report)
                    else:
                        st.warning("No report data available")
                        
                except Exception as e:
                    st.error(f"Error fetching VirusTotal report: {str(e)}")
        
        # URLScan.io Report Tab
        with tab3:
            st.subheader("URLScan.io Analysis Report")
            with st.spinner("Scanning URL with URLScan.io (this may take a moment)..."):
                try:
                    urlscan_report = scan_url(url_input)
                    
                    if urlscan_report:
                        # Display key information
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            if "task" in urlscan_report:
                                task = urlscan_report["task"]
                                st.markdown("### 📋 Scan Information")
                                if "url" in task:
                                    st.write(f"**URL:** {task['url']}")
                                if "visibility" in task:
                                    st.write(f"**Visibility:** {task['visibility']}")
                                if "time" in task:
                                    st.write(f"**Scan Time:** {task['time']}")
                            
                            if "page" in urlscan_report:
                                page = urlscan_report["page"]
                                st.markdown("### 🌐 Page Information")
                                if "url" in page:
                                    st.write(f"**Final URL:** {page['url']}")
                                if "domain" in page:
                                    st.write(f"**Domain:** {page['domain']}")
                                if "ip" in page:
                                    st.write(f"**IP Address:** {page['ip']}")
                        
                        with col2:
                            if "verdicts" in urlscan_report:
                                verdicts = urlscan_report["verdicts"]
                                st.markdown("### ⚖️ Verdicts")
                                st.json(verdicts)
                            
                            if "stats" in urlscan_report:
                                stats = urlscan_report["stats"]
                                st.markdown("### 📊 Statistics")
                                st.json(stats)
                        
                        # Full report in expander
                        with st.expander("📄 View Full URLScan.io Report"):
                            st.json(urlscan_report)
                    else:
                        st.warning("No report data available")
                        
                except Exception as e:
                    st.error(f"Error fetching URLScan.io report: {str(e)}")
        
        st.success("✅ Analysis complete!")

elif submit_button and not url_input:
    st.error("Please enter a URL to analyze")

