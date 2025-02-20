from packet_sniffer import sniffer
from anomaly_detector import AnomalyDetector
from gui import NetworkMonitorGUI
import threading
import tkinter as tk
import asyncio
import pyshark
import sqlite3


class NetworkSniffer:
    def __init__(self, interface="Wi-Fi"):
        self.interface = interface

    async def capture_packets(self, packet_count=10):
        print("[*] Starting async packet capture...")
        cap = pyshark.LiveCapture(interface=self.interface)
        packets = []
    
        async for packet in cap:
            print(f"Packet captured: {packet}")
            packets.append(packet)
            if len(packets) >= packet_count:
                break

        cap.close()
        return packets

    def start_capture(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(self.capture_packets())
        except Exception as e:
            print(f"[ERROR] Packet capture failed: {e}")
            return []


def init_database():
    conn = sqlite3.connect("anomalies.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            src_location TEXT,
            dst_ip TEXT,
            dst_location TEXT,
            protocol TEXT,
            length INTEGER,
            threat_level TEXT
        )
    """)
    conn.commit()
    conn.close()


def start_sniffing():
    print("[*] Starting packet capture...")
    sniffer.start_sniffing()


def start_gui():
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    print("🔥 Network Anomaly Detector is running...")

    init_database()

    sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffing_thread.start()

    start_gui()
