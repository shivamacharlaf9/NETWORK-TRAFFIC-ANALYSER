from PyQt5 import QtWidgets, QtGui, QtCore
import sys
import scapy.all as scapy
import pyqtgraph as pg
import os
import time
import json
import csv

class PacketAnalyzer(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        # Set up the main window layout
        self.setWindowTitle("Advanced Network Traffic Analyzer")
        self.setGeometry(100, 100, 1200, 800)
        main_layout = QtWidgets.QHBoxLayout(self)

        # Left panel for controls
        self.control_panel = QtWidgets.QFrame(self)
        self.control_panel.setFixedWidth(200)
        control_layout = QtWidgets.QVBoxLayout(self.control_panel)

        # Buttons for control panel
        self.start_btn = QtWidgets.QPushButton("Start Capture")
        self.stop_btn = QtWidgets.QPushButton("Stop Capture")
        self.stop_btn.setDisabled(True)
        self.save_btn = QtWidgets.QPushButton("Save Report")
        self.save_btn.setDisabled(True)
        self.export_btn = QtWidgets.QPushButton("Export CSV")
        self.export_btn.setDisabled(True)
        self.load_btn = QtWidgets.QPushButton("Load Historical Data")
        self.filter_btn = QtWidgets.QPushButton("Filter Traffic")
        self.export_pcap_btn = QtWidgets.QPushButton("Export to PCAP")
        self.export_pcap_btn.setDisabled(True)

        # Adding tooltips to buttons for UI enhancement
        self.start_btn.setToolTip("Start packet capture.")
        self.stop_btn.setToolTip("Stop the ongoing packet capture.")
        self.save_btn.setToolTip("Save the captured data as a report.")
        self.export_btn.setToolTip("Export the data as a CSV file.")
        self.load_btn.setToolTip("Load previous capture data.")
        self.filter_btn.setToolTip("Apply filters to the captured traffic.")
        self.export_pcap_btn.setToolTip("Export the captured packets to a PCAP file.")

        # Adding buttons to control panel
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.save_btn)
        control_layout.addWidget(self.export_btn)
        control_layout.addWidget(self.load_btn)
        control_layout.addWidget(self.filter_btn)
        control_layout.addWidget(self.export_pcap_btn)
        main_layout.addWidget(self.control_panel)

        # Packet Display area (middle panel)
        self.packet_display = QtWidgets.QTextEdit()
        self.packet_display.setReadOnly(True)
        main_layout.addWidget(self.packet_display)

        # Graph panel (right side)
        self.graph_panel = pg.PlotWidget()
        self.graph_panel.setTitle("Packet Traffic and Bandwidth Analysis")
        self.graph_panel.setLabel('left', 'Packet Count / Bandwidth (Bytes/sec)')
        self.graph_panel.setLabel('bottom', 'Time (packets captured)')
        self.graph_panel.addLegend()
        self.graph_panel.showGrid(x=True, y=True, alpha=0.3)
        main_layout.addWidget(self.graph_panel)

        # Connect buttons to actions
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.save_btn.clicked.connect(self.save_report)
        self.export_btn.clicked.connect(self.export_csv)
        self.load_btn.clicked.connect(self.load_historical_data)
        self.filter_btn.clicked.connect(self.filter_traffic)
        self.export_pcap_btn.clicked.connect(self.export_to_pcap)

        # Initialize packet statistics and bandwidth data
        self.packet_stats = {"TCP": 0, "UDP": 0, "Other": 0}
        self.bandwidth_data = []
        self.time_data = []
        self.tcp_data = []
        self.udp_data = []
        self.other_data = []
        self.captured_packets = []

        # Initialize filter settings
        self.filter_protocol = None
        self.filter_ip = None
        self.filter_min_size = None
        self.filter_max_size = None

        # Initialize graph plots
        self.plot_curve_tcp = self.graph_panel.plot(pen='r', name="TCP")
        self.plot_curve_udp = self.graph_panel.plot(pen='b', name="UDP")
        self.plot_curve_other = self.graph_panel.plot(pen='g', name="Other")
        self.plot_curve_bandwidth = self.graph_panel.plot(pen='y', name="Bandwidth")

        

    def start_capture(self):
        """Start packet capture in a new thread."""
        self.start_btn.setDisabled(True)
        self.stop_btn.setDisabled(False)
        self.save_btn.setDisabled(False)
        self.export_btn.setDisabled(False)
        self.export_pcap_btn.setDisabled(False)
        self.packet_display.append("Starting packet capture...\n")

        # Start packet capture thread
        self.capture_thread = QtCore.QThread()
        self.worker = PacketCaptureWorker()
        self.worker.moveToThread(self.capture_thread)
        self.capture_thread.started.connect(self.worker.run)
        self.worker.packet_captured.connect(self.update_packet_display)
        self.worker.finished.connect(self.capture_thread.quit)
        self.worker.update_progress.connect(self.update_progress_bar)
        self.capture_thread.start()

    def stop_capture(self):
        """Stop packet capture."""
        self.worker.stop()
        self.start_btn.setDisabled(False)
        self.stop_btn.setDisabled(True)
        self.packet_display.append("Packet capture stopped.\n")

    def update_packet_display(self, packet_info, packet_size, raw_packet):
        """Update display with captured packet information."""
        try:
            # Apply filter before displaying the packet
            if self.filter_protocol and self.filter_protocol not in packet_info:
                return
            if self.filter_ip and self.filter_ip not in packet_info:
                return
            if self.filter_min_size and packet_size < self.filter_min_size:
                return
            if self.filter_max_size and packet_size > self.filter_max_size:
                return

            self.packet_display.append(packet_info)
            self.captured_packets.append(raw_packet)  # Store raw packet for PCAP export

            # Update packet stats
            if "Protocol: TCP" in packet_info:
                self.packet_stats["TCP"] += 1
            elif "Protocol: UDP" in packet_info:
                self.packet_stats["UDP"] += 1
            else:
                self.packet_stats["Other"] += 1

            # Update time and packet counts for graph
            time_point = len(self.time_data) + 1
            self.time_data.append(time_point)
            self.tcp_data.append(self.packet_stats["TCP"])
            self.udp_data.append(self.packet_stats["UDP"])
            self.other_data.append(self.packet_stats["Other"])
            self.bandwidth_data.append(packet_size)

            # Update graph and check for anomalies
            self.update_graph()
            self.check_anomalies()
        except Exception as e:
            self.packet_display.append(f"Error updating display: {str(e)}")

    def update_graph(self):
        """Update the graph with packet statistics and bandwidth."""
        self.plot_curve_tcp.setData(self.time_data, self.tcp_data)
        self.plot_curve_udp.setData(self.time_data, self.udp_data)
        self.plot_curve_other.setData(self.time_data, self.other_data)
        self.plot_curve_bandwidth.setData(self.time_data, self.bandwidth_data)

    def check_anomalies(self):
        """Detect and display anomalies if packet count spikes."""
        threshold = 100
        if self.packet_stats["TCP"] > threshold:
            self.packet_display.append("Alert: High TCP traffic detected!\n")
        if self.packet_stats["UDP"] > threshold:
            self.packet_display.append("Alert: High UDP traffic detected!\n")

    def save_report(self):
        """Save captured data as a JSON report."""
        try:
            data = {
                "packet_stats": self.packet_stats,
                "time_data": self.time_data,
                "tcp_data": self.tcp_data,
                "udp_data": self.udp_data,
                "other_data": self.other_data,
                "bandwidth_data": self.bandwidth_data
            }
            report_path = "network_traffic_report.json"
            with open(report_path, "w") as f:
                json.dump(data, f, indent=4)
            self.packet_display.append("Report saved successfully.\n")
        except Exception as e:
            self.packet_display.append(f"Error saving report: {str(e)}")

    def export_csv(self):
        """Export captured data as a CSV file."""
        try:
            data = {
                "Time": self.time_data,
                "TCP": self.tcp_data,
                "UDP": self.udp_data,
                "Other": self.other_data,
                "Bandwidth (Bytes/sec)": self.bandwidth_data
            }
            csv_path = "network_traffic_report.csv"
            with open(csv_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(data.keys())
                writer.writerows(zip(*data.values()))
            self.packet_display.append("Data exported as CSV.\n")
        except Exception as e:
            self.packet_display.append(f"Error exporting CSV: {str(e)}")

    def load_historical_data(self):
        """Load previous capture data (JSON file)."""
        try:
            report_path = QtWidgets.QFileDialog.getOpenFileName(self, "Open Report", "", "JSON Files (*.json)")[0]
            if not report_path:
                return
            with open(report_path, "r") as f:
                data = json.load(f)
            self.time_data = data["time_data"]
            self.tcp_data = data["tcp_data"]
            self.udp_data = data["udp_data"]
            self.other_data = data["other_data"]
            self.bandwidth_data = data["bandwidth_data"]
            self.packet_stats = data["packet_stats"]
            self.update_graph()
            self.packet_display.append("Historical data loaded.\n")
        except Exception as e:
            self.packet_display.append(f"Error loading data: {str(e)}")

    def filter_traffic(self):
        """Open a dialog to filter captured traffic based on specific criteria."""
        # Example filters
        self.filter_protocol = "TCP"
        self.filter_ip = "192.168.1.1"
        self.filter_min_size = 100
        self.filter_max_size = 500
        self.packet_display.append("Traffic filter applied.\n")

    def export_to_pcap(self):
        """Export captured packets to a PCAP file."""
        try:
            pcap_path = "captured_packets.pcap"
            scapy.wrpcap(pcap_path, self.captured_packets)
            self.packet_display.append("Data exported as PCAP.\n")
        except Exception as e:
            self.packet_display.append(f"Error exporting PCAP: {str(e)}")

    def update_progress_bar(self, value):
        """Update the progress bar value."""
        self.progress_bar.setValue(value)

class PacketCaptureWorker(QtCore.QObject):
    """Worker for packet capture."""
    packet_captured = QtCore.pyqtSignal(str, int, object)
    update_progress = QtCore.pyqtSignal(int)
    finished = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()
        self._running = True

    def run(self):
        def process_packet(packet):
            if not self._running:
                return
            packet_info = f"Packet: {packet.summary()}\n"
            packet_size = len(packet)
            self.packet_captured.emit(packet_info, packet_size, packet)

        scapy.sniff(prn=process_packet, stop_filter=lambda p: not self._running)
        self.finished.emit()

    def stop(self):
        self._running = False

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    analyzer = PacketAnalyzer()
    analyzer.show()
    sys.exit(app.exec_())
