import psutil
import socket
import subprocess
import time
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QGroupBox, QFormLayout
from PyQt5 import QtCore 

prev_bytes_sent = 0
prev_bytes_recv = 0
prev_time = time.time()

def get_wifi_details():
    try:
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True).stdout
        details = {}
        for line in result.splitlines():
            if "SSID" in line and "BSSID" not in line:
                details["SSID"] = line.split(":")[1].strip()
            if "Signal" in line:
                details["Signal Strength"] = line.split(":")[1].strip()
            if "Interface name" in line:
                details["Adapter Name"] = line.split(":")[1].strip()
            if "Radio type" in line:
                details["Connection Type"] = line.split(":")[1].strip()
        return details
    except Exception as e:
        return {"Error": str(e)}

def get_ip_addresses():
    ip_info = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                if iface not in ip_info:
                    ip_info[iface] = {}
                ip_info[iface]["IPv4"] = addr.address
            elif addr.family == socket.AF_INET6:
                if iface not in ip_info:
                    ip_info[iface] = {}
                ip_info[iface]["IPv6"] = addr.address
    return ip_info

def calculate_speeds(bytes_sent, bytes_recv, current_time):
    global prev_bytes_sent, prev_bytes_recv, prev_time

    elapsed_time = current_time - prev_time
    if elapsed_time == 0:
        return 0, 0

    upload_speed = ((bytes_sent - prev_bytes_sent) * 8) / (elapsed_time * 1_000_000)
    download_speed = ((bytes_recv - prev_bytes_recv) * 8) / (elapsed_time * 1_000_000)

    prev_bytes_sent = bytes_sent
    prev_bytes_recv = bytes_recv
    prev_time = current_time

    return upload_speed, download_speed

class NetworkMonitor(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Wi-Fi Monitor")
        self.setFixedSize(400, 350)
        self.setWindowFlag(QtCore.Qt.WindowStaysOnTopHint)

        layout = QVBoxLayout()

        self.wifi_frame = QGroupBox("Wi-Fi Details")
        wifi_layout = QFormLayout()
        self.adapter_name_label = QLabel("Adapter Name: N/A")
        self.ssid_label = QLabel("SSID: N/A")
        self.signal_strength_label = QLabel("Signal Strength: N/A")
        self.connection_type_label = QLabel("Connection Type: N/A")
        wifi_layout.addRow(self.adapter_name_label)
        wifi_layout.addRow(self.ssid_label)
        wifi_layout.addRow(self.signal_strength_label)
        wifi_layout.addRow(self.connection_type_label)
        self.wifi_frame.setLayout(wifi_layout)

        self.stats_frame = QGroupBox("Network Statistics")
        stats_layout = QFormLayout()
        self.bytes_sent_label = QLabel("Bytes Sent: N/A")
        self.bytes_recv_label = QLabel("Bytes Received: N/A")
        self.packets_sent_label = QLabel("Packets Sent: N/A")
        self.packets_recv_label = QLabel("Packets Received: N/A")
        stats_layout.addRow(self.bytes_sent_label)
        stats_layout.addRow(self.bytes_recv_label)
        stats_layout.addRow(self.packets_sent_label)
        stats_layout.addRow(self.packets_recv_label)
        self.stats_frame.setLayout(stats_layout)

        layout.addWidget(self.wifi_frame)
        layout.addWidget(self.stats_frame)

        self.setLayout(layout)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_ui)
        self.timer.start(2000)

    def update_ui(self):
        wifi_details = get_wifi_details()
        ip_addresses = get_ip_addresses()
        net_io = psutil.net_io_counters(pernic=True)
        wifi_info = [iface for iface in net_io if "Wi-Fi" in iface]

        if "Error" in wifi_details:
            self.adapter_name_label.setText(f"Error: {wifi_details['Error']}")
            self.ssid_label.setText("SSID: N/A")
            self.signal_strength_label.setText("Signal Strength: N/A")
            self.connection_type_label.setText("Connection Type: N/A")
        else:
            self.adapter_name_label.setText(f"Adapter Name: {wifi_details.get('Adapter Name', 'N/A')}")
            self.ssid_label.setText(f"SSID: {wifi_details.get('SSID', 'N/A')}")
            self.signal_strength_label.setText(f"Signal Strength: {wifi_details.get('Signal Strength', 'N/A')}")
            self.connection_type_label.setText(f"Connection Type: {wifi_details.get('Connection Type', 'N/A')}")

        if wifi_info:
            wifi_data = net_io[wifi_info[0]]
            self.bytes_sent_label.setText(f"Bytes Sent: {wifi_data.bytes_sent} B")
            self.bytes_recv_label.setText(f"Bytes Received: {wifi_data.bytes_recv} B")
            self.packets_sent_label.setText(f"Packets Sent: {wifi_data.packets_sent}")
            self.packets_recv_label.setText(f"Packets Received: {wifi_data.packets_recv}")

            current_time = time.time()
            upload_speed, download_speed = calculate_speeds(wifi_data.bytes_sent, wifi_data.bytes_recv, current_time)
        else:
            self.bytes_sent_label.setText("Bytes Sent: N/A")
            self.bytes_recv_label.setText("Bytes Received: N/A")
            self.packets_sent_label.setText("Packets Sent: N/A")
            self.packets_recv_label.setText("Packets Received: N/A")

if __name__ == "__main__":
    app = QApplication([])
    window = NetworkMonitor()
    window.show()
    app.exec_()
