Advanced Network Traffic Analyzer
Description:
The Advanced Network Traffic Analyzer is a robust application built using PyQt5 and Scapy to capture, display, and analyze network traffic in real-time. It provides insightful graphical representations of network data, allowing for deeper understanding and anomaly detection. This tool is ideal for network administrators, cybersecurity professionals, or anyone looking to analyze network traffic data efficiently.

Features
Real-time Packet Capture
Captures network packets in real-time and displays detailed information, including protocol, IP addresses, and packet size.

Control Panel for Easy Management

Start and stop packet capture.
Save captured data as a JSON report or export it as CSV or PCAP.
Load historical data for analysis and apply custom filters for traffic analysis.
Traffic Filtering Options
Allows filtering by protocol (TCP, UDP, etc.), IP address, and packet size range, providing focused insights into network traffic.

Anomaly Detection
Real-time detection and alerts for unusual traffic patterns or high-volume data spikes, assisting in identifying potential security issues.

Data Export Options
Export captured traffic data to JSON, CSV, and PCAP formats, enabling further analysis in external tools or integration into reports.

Graphical Representation
Displays packet traffic and bandwidth over time using PyQtGraph, with separate graphs for TCP, UDP, and other protocols, as well as overall bandwidth.

Technologies Used
PyQt5: For building a cross-platform, interactive GUI.
Scapy: For network packet capturing, parsing, and manipulation.
PyQtGraph: For plotting real-time graphs of packet traffic.
JSON and CSV Libraries: For saving and loading data in JSON and CSV formats.
How It Works
Start Capture
When the capture is started, the application initiates packet capturing in a background thread to ensure smooth GUI interaction.

Live Packet Display and Analysis
Captured packets are displayed in real-time with details such as packet summary, size, and protocol type. The application also stores raw packet data for potential export as PCAP.

Graph Updates and Anomaly Alerts
The traffic data is plotted in real-time. TCP, UDP, and other traffic types are graphed separately, while the bandwidth graph shows data rates over time. The application detects and notifies high traffic spikes or anomalies.

Data Export and Report Generation
Users can save traffic data as a JSON report or export packet details as CSV or PCAP for further analysis or record-keeping.

Historical Data Loading
Users can load previously captured JSON data to view or analyze historical traffic patterns.
