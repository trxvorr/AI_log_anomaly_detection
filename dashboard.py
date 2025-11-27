import streamlit as st
import pandas as pd
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import re
import os
from datetime import datetime

# --- PAGE CONFIG ---
st.set_page_config(page_title="Log Anomaly Detection Platform", layout="wide")

st.markdown("""
    <style>
    .main {
        background-color: #f5f7f9;
    }
    h1 {
        color: #2c3e50;
        font-family: 'Helvetica Neue', sans-serif;
    }
    .stMetric {
        background-color: #ffffff;
        padding: 15px;
        border-radius: 5px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER SECTION ---
st.title("Log Anomaly Detection Platform")
st.markdown("""
**System Status:** 🟢 Online | **Engine:** Isolation Forest (Unsupervised)

This platform utilizes machine learning to automatically baseline normal system behavior and detect anomalies in server logs. It supports ingestion from various enterprise environments.

**Supported Log Sources:**
* 🪟 **Windows Events** (Text Exports)
* 🐧 **Linux / Syslog** (Standard system logs)
* ☁️ **HDFS** (Hadoop Distributed File System)
* 🌐 **Apache / Nginx** (Web Access & Error logs)
""")
st.markdown("---")

# --- 1. SMART PARSING UTILITIES ---

def parse_line_metadata(line):
    """
    Tries to extract Timestamp and detect format.
    Returns: (datetime_object, format_name, is_error_flag)
    """
    line = line.strip()
    if not line: return None, None, 0
    
    timestamp = None
    log_format = "Unknown"
    
    # A. ISO 8601 (Modern Web/JSON) e.g., 2025-11-26T10:00:00
    match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
    if match:
        try:
            timestamp = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
            log_format = "ISO-8601"
        except: pass

    # B. Standard Server (Legacy) e.g., 2025-11-26 10:00:00
    if not timestamp:
        match = re.search(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        if match:
            try:
                timestamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                log_format = "Standard"
            except: pass

    # C. Apache/Nginx Access Log e.g., [26/Nov/2025:10:00:00]
    if not timestamp:
        match = re.search(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})', line)
        if match:
            try:
                timestamp = datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S")
                log_format = "Apache Access"
            except: pass

    # D. Apache Error Log e.g., [Sun Dec 04 04:47:44 2005]
    if not timestamp:
        match = re.search(r'\[([A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} \d{4})\]', line)
        if match:
            try:
                # Format: Day Month Date Time Year
                timestamp = datetime.strptime(match.group(1), "%a %b %d %H:%M:%S %Y")
                log_format = "Apache Error"
            except: pass

    # E. Syslog (Linux/Firewall) e.g., Nov 26 10:00:00
    if not timestamp:
        match = re.search(r'^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})', line)
        if match:
            try:
                timestamp = datetime.strptime(match.group(1), "%b %d %H:%M:%S")
                timestamp = timestamp.replace(year=datetime.now().year) # Syslog has no year
                log_format = "Syslog/Firewall"
            except: pass

    # F. HDFS/Hadoop Format e.g., 081109 203615
    if not timestamp:
        match = re.search(r'^(\d{6})\s(\d{6})', line)
        if match:
            try:
                date_part = match.group(1)
                time_part = match.group(2)
                timestamp = datetime.strptime(f"{date_part} {time_part}", "%y%m%d %H%M%S")
                log_format = "HDFS/Hadoop"
            except: pass

    # G. Windows / US Format e.g., 11/26/2025 10:00:00
    if not timestamp:
        match = re.search(r'^(\d{1,2}/\d{1,2}/\d{4})\s(\d{2}:\d{2}:\d{2})', line)
        if match:
            try:
                timestamp = datetime.strptime(f"{match.group(1)} {match.group(2)}", "%m/%d/%Y %H:%M:%S")
                log_format = "Windows/US"
            except: pass

    if not timestamp:
        return None, None, 0

    # --- Error Detection Logic ---
    line_upper = line.upper()
    is_error = 0
    
    # 1. Keywords
    if any(x in line_upper for x in ["ERROR", "FAIL", "CRITICAL", "REFUSED", "DENIED", "UNAUTHORIZED", "FATAL", "EXCEPTION"]):
        is_error = 1
        
    # 2. HTTP Status Codes (4xx, 5xx)
    if "HTTP" in line:
        status_match = re.search(r'\s(\d{3})\s', line)
        if status_match:
            try:
                code = int(status_match.group(1))
                if code >= 400: is_error = 1
            except: pass

    return timestamp, log_format, is_error

# --- 2. MAIN PARSER ---
@st.cache_data
def parse_log_file(uploaded_file):
    # SETUP: Configure Drain3 with Defaults
    config = TemplateMinerConfig() 
    config.profiling_enabled = False
    template_miner = TemplateMiner(config=config)

    parsed_data = []
    
    # Handle file input
    if isinstance(uploaded_file, str):
        if not os.path.exists(uploaded_file): return pd.DataFrame()
        content = open(uploaded_file, "r").readlines()
    else:
        stringio = uploaded_file.getvalue().decode("utf-8", errors='ignore')
        content = stringio.splitlines()

    for line in content:
        timestamp, fmt, is_err = parse_line_metadata(line)
        
        if timestamp:
            # Drain3: We feed the whole line as the "message"
            result = template_miner.add_log_message(line.strip())
            template_id = result["cluster_id"]
            
            parsed_data.append({
                "timestamp": timestamp,
                "event_id": template_id,
                "message": line.strip(),
                "is_error": is_err,
                "format": fmt
            })
            
    return pd.DataFrame(parsed_data)

# --- SIDEBAR CONTROLS ---
st.sidebar.header("Configuration")
uploaded_file = st.sidebar.file_uploader("Upload Log File", type=["log", "txt", "csv"], help="Supports standard text logs")
contamination = st.sidebar.slider("Model Sensitivity", 0.001, 0.05, 0.01, format="%.3f", help="Adjust detection threshold")

# Load Data
data_source = "server_logs.log"
if uploaded_file:
    data_source = uploaded_file

# Run Parsing
with st.spinner("Ingesting and processing logs..."):
    df = parse_log_file(data_source)

if df.empty:
    st.warning("No valid log data found. Please upload a supported log file.")
    st.stop()

# Display Stats
fmt_type = df['format'].mode()[0]
st.sidebar.success(f"Detected Format: {fmt_type}")
st.sidebar.info(f"Processed {len(df)} lines")

# --- 3. FEATURE ENGINEERING ---
df.set_index("timestamp", inplace=True)
X = df.resample('1min').agg({'event_id': 'count', 'is_error': 'sum'})
X.columns = ['total_volume', 'error_count']
X.fillna(0, inplace=True)

# --- 4. TRAIN MODEL ---
model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
X['anomaly_score'] = model.fit_predict(X[['total_volume', 'error_count']])
anomalies = X[X['anomaly_score'] == -1]

# --- 5. DASHBOARD VISUALS ---
col1, col2, col3 = st.columns(3)
col1.metric("Analysed Time Window", f"{len(X)} Minutes")
col2.metric("Anomalies Detected", len(anomalies))
col3.metric("Overall Error Rate", f"{(df['is_error'].sum()/len(df))*100:.2f}%")

st.subheader("Traffic Analysis & Anomaly Detection")

# --- MATPLOTLIB GRAPH ---
fig, ax = plt.subplots(figsize=(12, 5))

# Plot Normal Traffic
ax.plot(X.index, X['total_volume'], label='Traffic Volume', color='#1f77b4', alpha=0.6, linewidth=1.5)

# Plot Anomalies with a "Halo" effect for visibility
ax.scatter(anomalies.index, anomalies['total_volume'], color='#d62728', label='Anomaly Detected', s=100, zorder=5, edgecolors='white', linewidth=1.5)

# Clean up the graph
ax.set_ylabel("Log Events (Per Minute)", fontsize=10, fontweight='bold', color='#2c3e50')
ax.set_xlabel("Timeline", fontsize=10, fontweight='bold', color='#2c3e50')
ax.grid(True, which='both', linestyle='--', linewidth=0.5, alpha=0.5)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.legend(frameon=True, loc='upper right')

# Format Date axis
ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
fig.tight_layout()

st.pyplot(fig)

# --- DRILL DOWN ---
if not anomalies.empty:
    st.subheader("Anomaly Investigation Console")
    selected_time = st.selectbox("Select a flagged timestamp to inspect:", anomalies.index)
    
    start = selected_time
    end = selected_time + pd.Timedelta(minutes=1)
    drill = df[(df.index >= start) & (df.index < end)]
    
    st.write(f"**Raw Log Data for {selected_time.strftime('%H:%M:%S')}:**")
    st.dataframe(drill[['message', 'is_error']], use_container_width=True)
else:
    st.success("✅ No anomalies detected. System behavior appears normal.")

with st.expander("View Full Raw Dataset"):

    st.dataframe(df)
