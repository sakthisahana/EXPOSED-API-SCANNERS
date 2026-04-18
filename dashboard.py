import streamlit as st
import requests
import pandas as pd
import json

# Configuration
API_URL = "http://127.0.0.1:5000"

st.set_page_config(page_title="Risk-Based Security Scanner", layout="wide")

st.title("🛡️ Risk-Based API Exposure Scanner")
st.markdown("### Information Security Management Dashboard")

# Sidebar for controls
st.sidebar.header("Control Panel")
repo_path = st.sidebar.text_input("Repository Path", "./vulnerable_repo")

if st.sidebar.button("🚀 Run Live Scan"):
    with st.spinner("Scanning Repository..."):
        try:
            response = requests.post(f"{API_URL}/scan", json={"path": repo_path})
            if response.status_code == 200:
                st.sidebar.success("Scan Complete!")
                st.session_state['scan_data'] = response.json()['results']
            else:
                st.sidebar.error("Scan Failed")
        except Exception as e:
            st.sidebar.error(f"Connection Error: {e}")

# Main Dashboard Area
if 'scan_data' in st.session_state and st.session_state['scan_data']:
    data = st.session_state['scan_data']
    
    # 1. Top Metrics
    col1, col2, col3 = st.columns(3)
    critical_count = sum(1 for x in data if x['risk']['level'] == 'CRITICAL')
    high_count = sum(1 for x in data if x['risk']['level'] == 'HIGH')
    
    col1.metric("Total Exposures", len(data))
    col2.metric("Critical Risks", critical_count, delta_color="inverse")
    col3.metric("Policies Violated", sum(len(x['policies_violated']) for x in data))

    st.divider()

    # 2. Detailed Findings
    st.subheader("🔍 Detected Vulnerabilities")
    
    for idx, item in enumerate(data):
        with st.expander(f"{item['finding']['severity']} | {item['finding']['signature']} in {item['finding']['file']}"):
            
            c1, c2 = st.columns(2)
            
            with c1:
                st.markdown("**Risk Assessment**")
                st.progress(item['risk']['score'])
                st.write(f"Risk Score: **{item['risk']['score']}/100**")
                st.write(f"Risk Level: **{item['risk']['level']}**")
            
            with c2:
                st.markdown("**Compliance & Policy**")
                for policy in item['policies_violated']:
                    st.error(f"⛔ Violated: {policy}")
            
            # Mitigation Action
            if st.button(f"🛠️ Auto-Mitigate Finding #{idx+1}", key=idx):
                with st.spinner("Revoking keys and patching code..."):
                    mit_response = requests.post(f"{API_URL}/mitigate", json={"finding": item['finding']})
                    if mit_response.status_code == 200:
                        st.success(f"Result: {mit_response.json()['action']}")
                        st.balloons()

else:
    st.info("No scan data available. Start a scan from the sidebar.")

# History Section
st.divider()
st.subheader("📜 Scan History")
if st.button("Refresh History"):
    hist = requests.get(f"{API_URL}/history").json()
    st.json(hist)