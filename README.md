# Hybrid AI Log Anomaly Detection Platform

A cybersecurity tool that combines heuristic feature engineering with unsupervised machine learning to detect anomalies in server logs. It utilizes Isolation Forests to identify statistical outliers (Volume Spikes, Error Bursts) and Drain3 for semantic template parsing.

## Features

- **Universal Log Parsing:** Auto-detects and parses Apache/Nginx, Syslog (Linux), Windows CBS, and HDFS formats.

- **Unsupervised Learning:** Uses a rule-based layer to extract error signals (keywords/status codes) which are then fed into an Isolation Forest to establish a dynamic baseline for normality

- **Interactive Dashboard:** Built with Streamlit to visualize traffic patterns and drill down into specific anomaly timestamps to reduce alert fatigue.

- **Semantic Analysis:** Uses Drain3 to group unstructured log messages into structured templates, reducing millions of raw lines into manageable event categories.

## Screenshots
<img width="1833" height="817" alt="image" src="https://github.com/user-attachments/assets/8f939bb8-9465-453c-81c3-f46c8fe2a8b2" />

<img width="1497" height="764" alt="image" src="https://github.com/user-attachments/assets/17f9d0db-cfc7-4c9a-b3b6-04bfe230bee1" />



## Architecture

1. **Ingestion:** Python-based parser with regex auto-detection for timestamp formats (ISO 8601, CLF, Syslog).

2. **Parsing:** Drain3 algorithm converts raw log text into "Event IDs" (Templates).

3. **Feature Engineering:** Extracts input features by aggregating Log Volume and Error Keywords (e.g., "Failed", "403", "CRITICAL") into 1-minute time windows.

4. **Detection:** An Isolation Forest model consumes these features to detect time windows that statistically deviate from the learned baseline (e.g., High Volume + High Error Rate).

5. **Visualization:** Matplotlib & Streamlit frontend for analyst review.

## Installation

### Clone the repository
```
git clone https://github.com/trxvorr/AI_log_anomaly_detection.git
cd ai-log-scanner
```

### Install Dependencies
```
pip install -r requirements.txt
```

## Usage
```
streamlit run dashboard.py
```
### To test with Industry Standard Data:
1. Download the public HDFS dataset ([Loghub](https://github.com/logpai/loghub/blob/master/HDFS/HDFS_2k.log)):

2. Then upload HDFS_2k.log in the dashboard sidebar.

## Performance

The model was rigorously benchmarked against the HDFS_2k dataset.

- Detection Capability: Successfully identified 51 critical failure clusters (Block Terminations, IO Exceptions) that manifested as statistical outliers.

- Burst Detection: Achieved near 100% detection for high-velocity "Burst Attacks" and Denial of Service (DoS) simulations.

- Compatibility: The parsing engine was validated against Windows CBS, Linux Syslog, and Apache Access logs to ensure cross-platform compatibility.

## Current Limitations

- **Sequence Blindness:** The current Isolation Forest model aggregates data by time windows. It excels at detecting volume/density anomalies but misses semantic anomalies where the order of events is invalid (e.g., a "bypass" attack that uses valid log lines in the wrong sequence).

- **Batch Latency:** The system processes static log files. Real-time threat detection requires a streaming architecture to reduce latency.

- **Dependency on Heuristics:** The "Error Rate" feature relies on a predefined list of generic keywords (ERROR, FAIL, HTTP 4xx). Highly specific application logic errors (e.g., "Transaction Reversed") might be missed without custom feature engineering.

## Future Improvements

- Integration with Deep Learning (LSTM) for sequence-based anomaly detection to address "Sequence Blindness."

- Real-time log ingestion via Apache Kafka pipeline.

- Feedback loop for analysts to label False Positives, enabling Semi-Supervised retraining.
