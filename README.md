# PCAP-Analyzer-AI-Powered-Network-Issue-Detection-for-Trading-Systems

## Demo: 
![Demo Preview](https://github.com/prernabanthiya/PCAP-Analyzer-AI-Powered-Network-Issue-Detection-for-Trading-Systems/blob/main/demo.mp4.gif?raw=true)

## Project Overview 

PCAP Analyzer is a Streamlit-based application designed to parse and analyze network packet capture (PCAP) files (and equivalent CSV exports) to identify critical issues in electronic trading environments. By leveraging Scapy for packet-level feature extraction and integrating a conversational AI assistant via OpenRouter, this tool helps Site Reliability Engineers (SREs), network engineers, and quant teams quickly diagnose anomalies such as retransmissions, duplicates, rejections, latency spikes, and disconnections.

## Key Features

* PCAP & CSV Support: Upload .pcap, .pcapng, or .csv files to ingest trading packet data.

__Dynamic Feature Extraction:__

* Retransmissions: Detect duplicate sequence numbers.

- Duplicates: Identify repeated payloads.

- Latency Measurement: Compute inter-packet delays per flow.

- Rejections: Flag packets containing error or rejection keywords.

- Disconnections: Detect FIN or RST flags indicating session termination.

__Interactive Dashboard:__

* Summary metrics (total packets, retransmissions, duplicates, etc.).

- Filter by source/destination IP, time range, and issue types.

- Visualizations: latency-over-time chart, top-talkers bar chart, and issue breakdown pie chart.

- AI-Powered Insights: Ask natural-language questions (e.g., "Why are there retransmissions?") to a fine-tuned LLM via the OpenRouter API, with contextual sample packets in the prompt.

- Modular Design: Separates parsing, feature computation, visualization, and AI logic for easy maintenance and extension.
  
## Tech Stack 
- Layer: Tools/Tech
- Frontend: Streamlit
- Backend	Python: Scapy
- AI/LLM: OpenRouter 
- Data Handling: Pandas, NumPy
- Visualization: Matplotlib, Seaborn, Plotly

## Prerequisites

* Python 3.8+

* pip package manager

* PCAP files (.pcap or .pcapng) or pre-exported CSVs of packet data

* OpenRouter API key (set in .env as OPENROUTER_API_KEY)

## Usage

1. Upload a PCAP or CSV file via the file uploader.

2. View summary metrics and a preview of parsed packets.

3. Interact with filters on the sidebar (IP selectors, time slider, issue toggles).

4. Explore visualizations updating in real-time.

5. Ask AI: Type a question about the data (e.g., cause of high latency), and the integrated LLM will provide explanations.






