from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import threading

class PacketSniffer:
    def __init__(self, interface="Wi-Fi"):
        self.interface = interface
        self.packet_data = []
        self.lock = threading.Lock()

    def process_packet(self, packet):
        if packet.haslayer(IP):
            try:
                pkt_info = {
                    "timestamp": packet.time,
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "protocol": "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other",
                    "length": len(packet),
                    "flags": packet[TCP].flags if packet.haslayer(TCP) else None
                }

                with self.lock:
                    self.packet_data.append(pkt_info)
                    if len(self.packet_data) > 50:
                        self.packet_data.pop(0)
            except Exception as e:
                print(f"[ERROR] Failed to process packet: {e}")

    def start_sniffing(self):
        print("[*] Starting packet capture on interface:", self.interface)
        sniff(iface=self.interface, prn=self.process_packet, store=False, filter="ip")

    def get_latest_packets(self):
        with self.lock:  # Ensure safe access
            return pd.DataFrame(self.packet_data[-10:])


sniffer = PacketSniffer()
sniffing_thread = threading.Thread(target=sniffer.start_sniffing, daemon=True)
sniffing_thread.start()
