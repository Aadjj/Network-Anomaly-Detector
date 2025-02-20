import tkinter as tk
from tkinter import ttk, messagebox
import requests
import threading
import ipaddress
from packet_sniffer import sniffer
from security import SecurityMonitor


class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Anomaly Detector")

        main_frame = tk.Frame(root)
        main_frame.pack(fill="both", expand=True)

        columns = ("Timestamp", "Source IP", "Source Location", "Destination IP", "Destination Location", "Protocol", "Length", "Anomaly")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")

        self.tree.pack(fill="both", expand=True)

        anomaly_label = tk.Label(root, text="⚠ Anomaly Log", font=("Arial", 12, "bold"), fg="red")
        anomaly_label.pack(pady=5)

        anomaly_columns = ("Timestamp", "Source IP", "Source Location", "Destination IP", "Destination Location", "Protocol", "Packet Length")
        self.anomaly_tree = ttk.Treeview(root, columns=anomaly_columns, show="headings")

        for col in anomaly_columns:
            self.anomaly_tree.heading(col, text=col)
            self.anomaly_tree.column(col, anchor="center")

        self.anomaly_tree.pack(fill="both", expand=True, pady=5)

        self.anomaly_tree.bind("<Double-1>", self.copy_anomaly_to_clipboard)

        self.detector = SecurityMonitor()
        self.detected_anomalies = set()
        self.ip_cache = {}

        self.root.after(2000, self.update_table)

    def is_private_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return True

    def get_ip_location(self, ip, callback):
        if ip in self.ip_cache:
            callback(ip, self.ip_cache[ip])
            return

        if self.is_private_ip(ip):
            self.ip_cache[ip] = "Local Network"
            callback(ip, "Local Network")
            return

        def fetch():
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
                location = f"{response.get('city', 'Unknown')}, {response.get('country', 'Unknown')}" if response["status"] == "success" else "Unknown"
            except requests.exceptions.RequestException:
                location = "Unknown"

            self.ip_cache[ip] = location
            self.root.after(0, callback, ip, location)

        threading.Thread(target=fetch, daemon=True).start()

    def update_table(self):
        packets = sniffer.get_latest_packets()

        existing_items = {self.tree.item(item, "values")[0]: item for item in self.tree.get_children()}

        for _, packet in packets.iterrows():
            src_ip = packet["src_ip"]
            dst_ip = packet["dst_ip"]
            timestamp = packet["timestamp"]

            anomaly_key = (timestamp, src_ip, dst_ip)
            is_anomaly = self.detector.detect([packet["length"]])[0]

            if timestamp in existing_items:
                tree_item = existing_items[timestamp]
                values = list(self.tree.item(tree_item, "values"))
                values[6] = "⚠ Anomaly" if is_anomaly else "✔ Normal"
                self.tree.item(tree_item, values=values)
            else:
                tree_item = self.tree.insert("", "end", values=(
                    timestamp, src_ip, "Loading...", dst_ip, "Loading...", packet["protocol"], packet["length"],
                    "⚠ Anomaly" if is_anomaly else "✔ Normal"
                ))

            self.get_ip_location(src_ip, lambda ip, loc: self.update_tree(tree_item, 2, loc))
            self.get_ip_location(dst_ip, lambda ip, loc: self.update_tree(tree_item, 4, loc))

            if is_anomaly and anomaly_key not in self.detected_anomalies:
                self.detected_anomalies.add(anomaly_key)
                self.add_to_anomaly_log(packet)

        self.root.after(2000, self.update_table)

    def update_tree(self, item, column, value):
        values = list(self.tree.item(item, "values"))
        values[column] = value
        self.tree.item(item, values=values)

    def add_to_anomaly_log(self, packet):
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]

        src_location = self.ip_cache.get(src_ip, "Fetching...")
        dst_location = self.ip_cache.get(dst_ip, "Fetching...")

        tree_item = self.anomaly_tree.insert("", "end", values=(
            packet["timestamp"], src_ip, src_location, dst_ip, dst_location, packet["protocol"], packet["length"]
        ))

        self.get_ip_location(src_ip, lambda ip, loc: self.update_tree(tree_item, 2, loc))
        self.get_ip_location(dst_ip, lambda ip, loc: self.update_tree(tree_item, 4, loc))

    def copy_anomaly_to_clipboard(self, event):
        selected_item = self.anomaly_tree.selection()
        if not selected_item:
            return

        values = self.anomaly_tree.item(selected_item[0], "values")
        anomaly_info = (
            f"Timestamp: {values[0]}\n"
            f"Source IP: {values[1]} ({values[2]})\n"
            f"Destination IP: {values[3]} ({values[4]})\n"
            f"Protocol: {values[5]}\n"
            f"Packet Length: {values[6]}"
        )

        self.root.clipboard_clear()
        self.root.clipboard_append(anomaly_info)
        self.root.update()
        messagebox.showinfo("Copied", "Anomaly details copied to clipboard!")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()
