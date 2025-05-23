import streamlit as st
import pandas as pd
import io
from scapy.all import rdpcap, TCP, IP
from datetime import datetime
from llm_helper import ask_llm

# ---- Feature Extraction from PCAP ----
def parse_pcap(file_bytes):
    packets = rdpcap(io.BytesIO(file_bytes))
    all_records = []  #it will store packet info
    seen_sequences = set()  #find retransmissions (same sequence number)
    seen_payloads = set()   # find duplicate data
    last_timestamps = {}    #calculate latency (time between packets)

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]

            timestamp = pkt.time
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            seq = tcp_layer.seq
            ack = tcp_layer.ack
            flags = str(tcp_layer.flags)
            payload_len = len(tcp_layer.payload)
            pkt_len = len(pkt)

            raw_payload = bytes(tcp_layer.payload)
            try:
                payload_str = raw_payload.decode('utf-8', errors='ignore')
            except:
                payload_str = ''

            flow_key = (src_ip, dst_ip, src_port, dst_port, seq)
            retransmission = flow_key in seen_sequences
            if not retransmission:
                seen_sequences.add(flow_key)

            payload_key = (src_ip, dst_ip, src_port, dst_port, raw_payload)
            duplicate = payload_key in seen_payloads
            if not duplicate and payload_len > 0:
                seen_payloads.add(payload_key)

            latency = None
            flow_id = (src_ip, dst_ip, src_port, dst_port)
            if flow_id in last_timestamps:
                latency = float(timestamp) - float(last_timestamps[flow_id])
            last_timestamps[flow_id] = float(timestamp)

            rejection_keywords = ['Reject', 'rejected', 'error', 'Invalid', 'Risk', 'Limit']
            rejection_detected = any(keyword.lower() in payload_str.lower() for keyword in rejection_keywords)

            disconnection_detected = 'F' in flags or 'R' in flags

            all_records.append({
                'timestamp': datetime.fromtimestamp(float(timestamp)),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': 'TCP',
                'seq': seq,
                'ack': ack,
                'tcp_flags': flags,
                'payload_size': payload_len,
                'packet_length': pkt_len,
                'payload_str': payload_str,
                'retransmission': retransmission,
                'duplicate': duplicate,
                'latency_sec': latency,
                'rejected': rejection_detected,
                'disconnected': disconnection_detected
            })

    return pd.DataFrame(all_records)

# ---- Dynamic Feature Computation from CSV ----
def compute_features_if_missing(df):
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

        # Try reconstructing payload_str if missing but payload_bytes exists
        if 'payload_str' not in df.columns:
            if 'payload_bytes' in df.columns:
                def decode_payload(x):
                    try:
                        if isinstance(x, bytes):
                            return x.decode('utf-8', errors='ignore')
                        elif isinstance(x, str):
                            return bytes.fromhex(x).decode('utf-8', errors='ignore')
                    except:
                        return ''
                    return ''

                df['payload_str'] = df['payload_bytes'].apply(decode_payload)
            else:
                df['payload_str'] = ''

    if 'retransmission' not in df.columns:
        seen = set()
        retrans = []
        for _, row in df.iterrows():
            key = (row.get('src_ip'), row.get('dst_ip'), row.get('src_port'), row.get('dst_port'), row.get('seq'))
            retrans.append(key in seen)
            seen.add(key)
        df['retransmission'] = retrans

    if 'duplicate' not in df.columns:
        seen_payloads = set()
        duplicates = []
        for _, row in df.iterrows():
            payload = row.get('payload_str', None)
            key = (row.get('src_ip'), row.get('dst_ip'), row.get('src_port'), row.get('dst_port'), payload)
            duplicates.append(key in seen_payloads)
            if payload:
                seen_payloads.add(key)
        df['duplicate'] = duplicates

    if 'latency_sec' not in df.columns:
        last_ts = {}
        latencies = []
        for _, row in df.iterrows():
            flow_id = (row.get('src_ip'), row.get('dst_ip'), row.get('src_port'), row.get('dst_port'))
            ts = row.get('timestamp')
            if flow_id in last_ts and pd.notna(ts):
                latencies.append((ts - last_ts[flow_id]).total_seconds())
            else:
                latencies.append(None)
            last_ts[flow_id] = ts
        df['latency_sec'] = latencies

    if 'rejected' not in df.columns:
        keywords = ['reject', 'rejected', 'error', 'invalid', 'risk', 'limit']
        df['rejected'] = df['payload_str'].fillna('').str.lower().apply(lambda x: any(k in x for k in keywords))

    if 'disconnected' not in df.columns:
        df['disconnected'] = df['tcp_flags'].fillna('').apply(lambda x: 'F' in x or 'R' in x)

    return df

# ---- Streamlit App ----
st.title("PCAP Analyzer: AI-Powered Network Issue Detection for Trading Systems")

st.write("Upload a PCAP or CSV file to analyze trading packet data for anomalies.")
file = st.file_uploader("Upload PCAP or CSV", type=["pcap", "pcapng", "csv"])

if file:
    if file.name.endswith('.csv'):
        df = pd.read_csv(file)
    else:
        file_bytes = file.read()
        df = parse_pcap(file_bytes)

    df = compute_features_if_missing(df)
    st.success("File parsed and features computed successfully.")
    st.dataframe(df.head())

    st.write("### Summary Metrics")
    st.metric("Total Packets", len(df))
    st.metric("Retransmissions", int(df['retransmission'].sum()))
    st.metric("Duplicates", int(df['duplicate'].sum()))
    st.metric("Rejected Packets", int(df['rejected'].sum()))
    st.metric("Disconnected Sessions", int(df['disconnected'].sum()))

    latency_vals = df['latency_sec'].dropna()
    if not latency_vals.empty:
        st.write(f"Latency - Mean: {latency_vals.mean():.6f} sec | Max: {latency_vals.max():.6f} sec")
    else:
        st.write("Latency data not available.")

    st.write("### Ask AI about Network Issues")

    # Use session state to track the input
    if "user_q" not in st.session_state:
        st.session_state.user_q = ""


    def submit():
        st.session_state.submitted_q = st.session_state.user_q
        st.session_state.user_q = ""  # Clear input field after submit


    # Input box with key bound to session state
    st.text_input("Ask a question (e.g., Why are there retransmissions?)",
                  key="user_q",
                  on_change=submit)

    # Only respond if a question was submitted
    if "submitted_q" in st.session_state and st.session_state.submitted_q:
        context_sample = df.head(2).to_dict(orient='records')  # keep this light for speed
        prompt = f"User question: {st.session_state.submitted_q}\nSample packets:\n{context_sample}\nPlease explain or troubleshoot."

        with st.spinner("Getting AI response..."):
            answer = ask_llm(prompt)

        st.markdown("###  AI Answer:")
        st.code(answer, language='markdown')

    # ---- Filters ----
    st.sidebar.markdown("### Filters")
    st.sidebar.markdown("Source IP")
    src_ips = st.sidebar.multiselect("Source IP", options=df['src_ip'].unique(), default=df['src_ip'].unique())
    st.sidebar.markdown("Destination IP")
    dst_ips = st.sidebar.multiselect("Destination IP", options=df['dst_ip'].unique(), default=df['dst_ip'].unique())

    # Convert pandas Timestamp to native Python datetime for slider
    start_time = df['timestamp'].min()
    end_time = df['timestamp'].max()
    start_time_py = start_time.to_pydatetime()
    end_time_py = end_time.to_pydatetime()

    if start_time_py == end_time_py:
        st.sidebar.write("Time Range slider disabled (only one timestamp available).")
        time_range = (start_time_py, end_time_py)
    else:
        time_range = st.sidebar.slider(
            "Time Range",
            min_value=start_time_py,
            max_value=end_time_py,
            value=(start_time_py, end_time_py)
        )

    show_retrans = st.sidebar.checkbox("Show Only Retransmissions", value=False)
    show_duplicates = st.sidebar.checkbox("Show Only Duplicates", value=False)
    show_rejections = st.sidebar.checkbox("Show Only Rejected", value=False)
    show_disconnections = st.sidebar.checkbox("Show Only Disconnected", value=False)

    # ---- Apply Filters ----
    filtered_df = df[
        (df['src_ip'].isin(src_ips)) &
        (df['dst_ip'].isin(dst_ips)) &
        (df['timestamp'] >= time_range[0]) &
        (df['timestamp'] <= time_range[1])
    ]

    if show_retrans:
        filtered_df = filtered_df[filtered_df['retransmission'] == True]
    if show_duplicates:
        filtered_df = filtered_df[filtered_df['duplicate'] == True]
    if show_rejections:
        filtered_df = filtered_df[filtered_df['rejected'] == True]
    if show_disconnections:
        filtered_df = filtered_df[filtered_df['disconnected'] == True]

    st.success(f"Filtered {len(filtered_df)} packets based on selected criteria.")
    st.dataframe(filtered_df.head())

    st.write("### Visualizations")

    st.write("Latency over time")
    if not filtered_df['latency_sec'].dropna().empty:
        st.line_chart(filtered_df.set_index('timestamp')['latency_sec'])

    st.write("Bar chart: Top source IPs")
    top_src = filtered_df['src_ip'].value_counts().head(10)
    st.bar_chart(top_src)

    #Pie chart: Issue breakdown
    import matplotlib.pyplot as plt

    issue_counts = {
        'Retransmissions': filtered_df['retransmission'].sum(),
        'Duplicates': filtered_df['duplicate'].sum(),
        'Rejected': filtered_df['rejected'].sum(),
        'Disconnected': filtered_df['disconnected'].sum()
    }

    # Clean NaNs and zeros
    issue_counts = {k: (v if pd.notna(v) else 0) for k, v in issue_counts.items()}
    issue_series = pd.Series(issue_counts)

    st.write("#### Issue Breakdown")

    if issue_series.sum() == 0:
        st.write("No detected issues to display in the pie chart.")
    else:
        fig, ax = plt.subplots()
        issue_series.plot.pie(autopct='%1.1f%%', figsize=(5, 5), ax=ax)
        st.pyplot(fig)


else:
    st.info("Upload a .pcap or .csv file to begin.")