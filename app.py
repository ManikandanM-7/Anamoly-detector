import streamlit as st
import pandas as pd
import os
import time
import glob
import altair as alt
import re
import zipfile
import io
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# --- Configuration ---
INPUT_DIR = "input_logs"
OUTPUT_DIR = "output_alerts"
STATUS_FILE = "_STATUS_DONE.txt"
JOB_TIMEOUT = 300
LOADING_GIF_PATH = "assets/loading.gif"
IDLE_IMAGE_PATH = "assets/idle.png"

st.set_page_config(
    layout="wide",
    page_title="SOC Analyst Dashboard | AI-Powered",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# --- Custom CSS ---
st.markdown("""
<style>
    .stApp { background-color: #0E1117; }
    h1 { color: #FFFFFF; text-shadow: 2px 2px 4px #000000; border-bottom: 2px solid #1F2937; padding-bottom: 10px; }
    h2, h3 { color: #38BDF8; }
    .stMetric { background-color: #1F2937; border: 1px solid #374151; }
    .stTabs [data-baseweb="tab"] { background-color: #1F2937; color: white; }
    .stTabs [aria-selected="true"] { background-color: #38BDF8 !important; color: black !important; }
</style>
""", unsafe_allow_html=True)

# --- AI Engine ---
def run_ai_detection(df, mode):
    """
    Runs Isolation Forest (Unsupervised Anomaly Detection)
    Adapts features based on the data type (Web vs Network).
    """
    try:
        # 1. Select Features based on Mode
        if mode == 'network':
            features = ['Total Fwd Packets', 'Total Backward Packets', 'Flow IAT Mean', 'Fwd Packet Length Mean']
            # Ensure columns exist and are numeric
            for f in features:
                if f not in df.columns: df[f] = 0
                df[f] = pd.to_numeric(df[f], errors='coerce').fillna(0)
        else: # 'web'
            # Feature Engineering for Logs
            # We count frequency of IP and Status Codes to find anomalies
            df['ip_count'] = df.groupby('ip')['ip'].transform('count')
            df['error_flag'] = df['status'].apply(lambda x: 1 if x >= 400 else 0)
            features = ['ip_count', 'error_flag']

        # 2. Prepare Data
        X = df[features].copy()

        # 3. Scale
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # 4. Detect
        # Contamination 'auto' lets the model decide the threshold
        iso = IsolationForest(contamination='auto', random_state=42)
        df['anomaly_score'] = iso.fit_predict(X_scaled)

        # -1 is anomaly, 1 is normal
        anomalies = df[df['anomaly_score'] == -1]
        return anomalies
    except Exception as e:
        st.error(f"AI Engine Error: {e}")
        return pd.DataFrame()

def parse_file(uploaded_file):
    """Smart Parser: Handling CSV, TXT, and LOG."""
    filename = uploaded_file.name.lower()

    # --- CASE A: Network CSV ---
    if filename.endswith('.csv'):
        try:
            df = pd.read_csv(uploaded_file)
            df.columns = [c.strip() for c in df.columns] # Clean headers
            # Simulate IP if missing (common in public datasets)
            if 'Source IP' not in df.columns and 'ip' not in df.columns:
                df['ip'] = [f"192.168.1.{i%255}" for i in range(len(df))]
            return df, 'network'
        except:
            return pd.DataFrame(), 'error'

    # --- CASE B: Web Access Log ---
    else:
        # Robust Apache Regex
        log_pattern = re.compile(r'^(\S+) \S+ \S+ \[(.+?)\] "(\S+) (\S+) \S+" (\d{3}) (\S+) "(.*?)" "(.*?)"')
        data = []
        uploaded_file.seek(0)
        # Try different encodings
        try:
            content = uploaded_file.getvalue().decode("utf-8").splitlines()
        except:
            content = uploaded_file.getvalue().decode("latin-1").splitlines()

        for line in content:
            match = log_pattern.match(line)
            if match:
                size_str = match.group(6)
                data.append({
                    'ip': match.group(1),
                    'timestamp': match.group(2),
                    'method': match.group(3),
                    'url': match.group(4),
                    'status': int(match.group(5)),
                    'size': int(size_str) if size_str.isdigit() else 0,
                    'user_agent': match.group(8)
                })

        if not data: return pd.DataFrame(), 'error'
        df = pd.DataFrame(data)
        # Parse time
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
        df = df.dropna(subset=['timestamp'])
        return df, 'web'

def create_zip(df_anom, filename):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"anomalies_{filename}.csv", df_anom.to_csv(index=False))
        zf.writestr("security_report.txt", f"AI Analysis Report\nTarget: {filename}\nThreats: {len(df_anom)}")
    return buf.getvalue()

# --- State Management ---
if "app_state" not in st.session_state: st.session_state.app_state = "idle"
if "raw_df" not in st.session_state: st.session_state.raw_df = None
if "anom_df" not in st.session_state: st.session_state.anom_df = None
if "file_type" not in st.session_state: st.session_state.file_type = None

# --- Sidebar ---
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/imac-settings.png", width=64)
    st.title("SOC Controls")
    st.info("AI Engine: **Active**")
    st.markdown("---")
    st.link_button("🔥 Open Spark UI", "http://localhost:4040")
    if st.button("Reset System", use_container_width=True):
        st.session_state.app_state = "idle"
        st.rerun()

# --- Main App ---
st.title("🛡️ SOC Analyst Dashboard | AI-Powered")

# --- VIEW 1: UPLOAD ---
if st.session_state.app_state == "idle":
    with st.container(border=True):
        st.header("📤 Ingest Data")

        # --- CORRECTED: Allow ALL file types ---
        uploaded_file = st.file_uploader(
            "Select Data Source (Network CSV or Web Log)",
            type=['csv', 'txt', 'log', 'xlsx'],
            accept_multiple_files=False
        )

        if st.button("🚀 Initiate AI Scan", type="primary", use_container_width=True):
            if uploaded_file:
                with st.spinner("Parsing and analyzing data structure..."):
                    df, f_type = parse_file(uploaded_file)

                    if f_type == 'error' or df.empty:
                        st.error("Could not parse file. Please ensure it is a valid Apache Log or Network CSV.")
                        st.stop()

                    # Run AI Immediately
                    anom_df = run_ai_detection(df, f_type)

                    st.session_state.raw_df = df
                    st.session_state.anom_df = anom_df
                    st.session_state.file_type = f_type
                    st.session_state.filename = uploaded_file.name

                    # Simulate processing time for "High Tech" feel
                    time.sleep(1.5)
                    st.session_state.app_state = "results"
                    st.rerun()
            else:
                st.warning("Please upload a file.")

    if os.path.exists(IDLE_IMAGE_PATH):
        st.image(IDLE_IMAGE_PATH, caption="Waiting for stream...", width=600)

# --- VIEW 2: RESULTS ---
elif st.session_state.app_state == "results":
    df = st.session_state.raw_df
    anom = st.session_state.anom_df
    ftype = st.session_state.file_type

    # Header
    c1, c2 = st.columns([3, 1])
    with c1: st.success(f"Analysis Complete: `{st.session_state.filename}`")
    with c2:
        if st.button("⬅️ New Scan"):
            st.session_state.app_state = "idle"
            st.rerun()

    if anom.empty:
        st.info("✅ System Healthy. No anomalies detected.")
    else:
        st.error(f"🚨 **CRITICAL:** {len(anom)} Anomalies Detected by Isolation Forest")

        # --- VISUALIZATION LOGIC ---
        t1, t2, t3 = st.tabs(["📊 Visual Forensics", "🧠 AI Insights", "📥 Evidence"])

        with t1:
            # --- WEB LOG CHARTS ---
            if ftype == 'web':
                c1, c2 = st.columns(2)
                with c1:
                    st.subheader("Top Attacking IPs")
                    chart = alt.Chart(anom).mark_bar().encode(
                        x="count()", y=alt.Y("ip", sort="-x"), color=alt.value("#FF4B4B")
                    )
                    st.altair_chart(chart, use_container_width=True)
                with c2:
                    st.subheader("Malicious Status Codes")
                    chart = alt.Chart(anom).mark_arc().encode(
                        theta="count()", color="status:N", tooltip=["status", "count()"]
                    )
                    st.altair_chart(chart, use_container_width=True)

                st.subheader("Attack Traffic over Time")
                ts = anom.set_index('timestamp').resample('1Min').size().reset_index(name='count')
                chart = alt.Chart(ts).mark_area(color='red', opacity=0.5).encode(
                    x="timestamp", y="count"
                )
                st.altair_chart(chart, use_container_width=True)

            # --- NETWORK CSV CHARTS ---
            else: # network
                c1, c2 = st.columns(2)
                with c1:
                    st.subheader("Packet Size Anomalies")
                    chart = alt.Chart(df).mark_circle(opacity=0.5).encode(
                        x=alt.X("Total Fwd Packets", scale=alt.Scale(type="symlog")),
                        y=alt.Y("Total Backward Packets", scale=alt.Scale(type="symlog")),
                        color=alt.condition(
                            alt.datum.anomaly_score == -1,
                            alt.value("red"),
                            alt.value("blue")
                        ),
                        tooltip=["Total Fwd Packets", "anomaly_score"]
                    )
                    st.altair_chart(chart, use_container_width=True)

                with c2:
                    st.subheader("Flow Duration vs Intervals")
                    chart = alt.Chart(anom).mark_bar().encode(
                        x=alt.X("Flow IAT Mean", bin=True),
                        y="count()",
                        color=alt.value("orange")
                    )
                    st.altair_chart(chart, use_container_width=True)

        with t2:
            st.subheader("🤖 Automated Threat Report")
            with st.container(border=True):
                if ftype == 'web':
                    top_ip = anom['ip'].mode()[0] if not anom.empty else "N/A"
                    st.markdown(f"**Primary Suspect:** `{top_ip}`")
                    st.write("The AI model detected anomalous web request patterns. High error rates and repetitive requests suggest a **Brute Force** or **Scanning** attempt.")
                else:
                    st.markdown("**Threat Type:** Network Anomaly (DDoS / Exfiltration)")
                    st.write("The Isolation Forest detected statistical outliers in packet flow. High packet counts with low inter-arrival times typically indicate **Volumetric DDoS**.")

        with t3:
            st.subheader("Raw Data Inspector")
            st.dataframe(anom)
            zip_file = create_zip(anom, st.session_state.filename)
            st.download_button("📦 Download Forensics Package", zip_file, "forensics.zip", "application/zip", type="primary")