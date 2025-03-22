# collectors/network_traffic.py
import logging
import threading
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

logger = logging.getLogger('sec-spot-agent.network')

class NetworkTrafficCollector:
    """Collector for network traffic using packet sniffing"""
    
    def __init__(self, callback=None, max_packets=100):
        """Initialize the network traffic collector
        
        Args:
            callback (callable): Function to call when packets reach max_packets
            max_packets (int): Maximum number of packets to collect before calling callback
        """
        self.callback = callback
        self.max_packets = max_packets
        self.packets = []
        self.stop_sniffing = threading.Event()
        self.sniff_thread = None
        self.lock = threading.Lock()  # For thread-safe packet collection
        
        logger.info("Network traffic collector initialized")
    
    def start(self):
        """Start packet sniffing in a separate thread"""
        self.stop_sniffing.clear()
        self.sniff_thread = threading.Thread(target=self._sniff_packets)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        logger.info("Network traffic monitoring started")
    
    def stop(self):
        """Stop packet sniffing"""
        self.stop_sniffing.set()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2)
        logger.info("Network traffic monitoring stopped")
    
    def _sniff_packets(self):
        """Sniff network packets"""
        try:
            sniff(prn=self._packet_callback, 
                  store=0, 
                  stop_filter=lambda _: self.stop_sniffing.is_set())
        except Exception as e:
            logger.error(f"Error in packet sniffing: {str(e)}")
    
    def _packet_callback(self, packet):
        """Callback function for packet sniffing
        
        Args:
            packet: Scapy packet object
        """
        if self.stop_sniffing.is_set():
            return
        
        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                
                # Determine protocol
                if TCP in packet:
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                else:
                    protocol = "Other"
                    src_port = None
                    dst_port = None
                
                size = len(packet)
                
                with self.lock:
                    # Store packet info
                    self.packets.append({
                        'from': ip_src,
                        'to': ip_dst,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'size': size,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    # Check if we've reached max_packets
                    if len(self.packets) >= self.max_packets and self.callback:
                        # Get a copy of the current packets and clear the list
                        packets_to_send = self.packets.copy()
                        self.packets = []
                        
                        # Call the callback with the collected packets
                        if not self.callback(packets_to_send):
                            # If callback returns False, put packets back
                            with self.lock:
                                self.packets = packets_to_send + self.packets
        
        except Exception as e:
            logger.error(f"Error in packet callback: {str(e)}")
    
    def get_collected_packets(self):
        """Get the currently collected packets
        
        Returns:
            list: Copy of the currently collected packets
        """
        with self.lock:
            return self.packets.copy()
    
    def clear_packets(self):
        """Clear the collected packets"""
        with self.lock:
            self.packets = []