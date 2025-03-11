import psutil
import pickle
import struct
import sqlite3
from scapy.all import sniff, TCP, UDP, IP
import socket

class TrafficMonitoring:
    def __init__(self):
        """Initialize the TrafficMonitoring class."""
        pass

    def capture_traffic(self, packet_count=10):
        """Capture network packets in real time."""
        def packet_callback(packet):
            if IP in packet:
                ip_layer = packet[IP]
                protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
                packet_info = {
                    "from": f"{ip_layer.src}:{packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 'N/A'}",
                    "to": f"{ip_layer.dst}:{packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 'N/A'}",
                    "protocol": protocol
                }
                packets.append(packet_info)  # Add to list of packets

        packets = []  # Initialize the list of packets
        print(f"Capturing {packet_count} packets... for host {self.get_machine_ip()}")
        sniff(count=packet_count, prn=packet_callback, store=False)
        print(packets)
        return packets

    def sync_traffic_with_server(self, server_socket, packet_range=20):
        """Capture and sync traffic with the server in batches of packet_range."""
        # Capture packets in the specified range
        packets = self.capture_traffic(packet_count=packet_range)
        print(packets)
        # Prepare data to send to the server
        data_to_send = pickle.dumps({"type": "traffic", "data": packets})  # Add a type key

        # Send captured packets to the remote server
        print(f"Sending {len(packets)} packets to the server...")
        server_socket.sendall(data_to_send)
        print("Packets sent successfully.")

    @staticmethod
    def get_machine_ip():
        """Retrieve the current machine's IP address."""
        hostname = socket.gethostname()
        return '192.168.29.128'
        return socket.gethostbyname(hostname)

    def save_traffic_to_database(self, db_connection):
        """Save captured network traffic to an SQLite database."""
        cursor = db_connection.cursor()

        # Create the traffic table if it doesn't exist, escaping the reserved word 'timestamp'
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                "timestamp" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sync INTEGER DEFAULT 0
            )
        ''')

        # Capture traffic to save
        packets = self.capture_traffic(packet_count=10)  # Capture 10 packets for this example

        # Insert traffic data into the database with sync = 0 (unsynced)
        for packet in packets:
            cursor.execute('''
                INSERT INTO network_traffic (source_ip, destination_ip, protocol, sync)
                VALUES (?, ?, ?, 0)
            ''', (packet['from'], packet['to'], packet['protocol']))

        # Commit the transaction
        db_connection.commit()
        print("Traffic data saved to database successfully.")
