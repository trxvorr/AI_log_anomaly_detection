# Unsupervised AI Log Anomaly Detection Platform

A machine learning-based cybersecurity tool that detects anomalies in server logs without requiring labeled training data. It utilizes Isolation Forests and Drain3 parsing to identify zero-day threats, volume spikes, and behavioral deviations across various log formats.

## Features

- **Universal Log Parsing:** Auto-detects and parses Apache/Nginx, Syslog (Linux), Windows CBS, and HDFS formats.

- **Unsupervised Learning:** Uses Isolation Forest to detect anomalies based on statistical density (Volume + Error Rate) rather than static signatures.

- **Interactive Dashboard:** Built with Streamlit to visualize traffic patterns and drill down into specific anomaly timestamps.

- **Semantic Analysis:** Uses Drain3 to group unstructured log messages into structured templates for better ML feature extraction.

## Screenshots
<img width="1833" height="817" alt="image" src="https://github.com/user-attachments/assets/8f939bb8-9465-453c-81c3-f46c8fe2a8b2" />

<img width="1497" height="764" alt="image" src="https://github.com/user-attachments/assets/17f9d0db-cfc7-4c9a-b3b6-04bfe230bee1" />



## Architecture

1. **Ingestion:** Python-based parser with regex auto-detection for timestamp formats (ISO 8601, CLF, Syslog).

2. **Parsing:** Drain3 algorithm converts raw log text into "Event IDs" (Templates).

3. **Feature Engineering:** Aggregates data into 1-minute time windows, calculating Log Volume and Error Count.

4. **Detection:** Isolation Forest (Scikit-Learn) flags time windows that deviate from the learned baseline.

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
Test the model against the public HDFS dataset ([Loghub](https://github.com/logpai/loghub/blob/master/HDFS/HDFS_2k.log)):

Then upload HDFS_2k.log in the dashboard sidebar.

## Performance

Benchmarked against the HDFS_2k, Windows_2k, Linux_2k, and Apache_2k datasets, the model successfully identified critical failure clusters (Block Terminations, System Errors, and IO Exceptions) purely based on behavioral patterns, achieving a high detection rate for burst anomalies across diverse environments.

## Current Limitations

- **Sequence Blindness:** The current Isolation Forest model aggregates data by time windows. It excels at detecting volume anomalies (DoS, Bursts) but misses semantic anomalies where the order of events is invalid (e.g., bypass attacks or "low and slow" intrusions).

- **Batch Latency:** The system processes static log files. Real-time threat detection requires a streaming architecture to reduce latency.

- **Domain Specificity:** While generic, the "Error Count" feature relies on broad keywords. Highly specific application logic errors might be missed without custom feature engineering.

## Future Improvements

- Integration with Deep Learning (LSTM) for sequence-based anomaly detection.

- Real-time log ingestion via Kafka pipeline.

- Feedback loop for analysts to label False Positives.
