from scapy.all import sniff, TCP, UDP, IP
import socket
import asyncio

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
                    "protocol": protocol,
                    "size": len(packet) 
                }
                packets.append(packet_info) 
        packets = [] 
        print(f"Capturing {packet_count} packets... for host {self.get_machine_ip()}")
        sniff(count=packet_count, prn=packet_callback, store=False)
        return packets

    @staticmethod
    def get_machine_ip():
        """Retrieve the current machine's IP address."""
        hostname = socket.gethostname()
        return '192.168.29.128'
        return socket.gethostbyname(hostname)

    async def start(self, client, sleep_time, batch_size=10):
        """Start capturing network traffic and send data to the server periodically in batches."""
        while True:
            batch_data = []
            for _ in range(batch_size):
                packets = self.capture_traffic(packet_count=1)  
                batch_data.extend(packets) 
            await client.send('network-traffic', batch_data)
            print(f"{len(batch_data)} packets sent to server.")
            await asyncio.sleep(sleep_time)