# collectors/network_traffic.py
import socket
import struct
import threading
import time
import logging
from datetime import datetime

logger = logging.getLogger('sec-spot-agent.network')


class NetworkTrafficCollector:
    """Collector for network traffic monitoring with improved batching"""

    def __init__(self, callback=None, max_packets=1000, batch_interval=60, interface=None):
        """Initialize the network traffic collector

        Args:
            callback (callable): Function to call when packets are collected
            max_packets (int): Maximum number of packets per batch (default: 1000)
            batch_interval (int): Maximum time between batches in seconds (default: 60)
            interface (str): Network interface to monitor (None for all)
        """
        self.callback = callback
        self.max_packets = max_packets
        self.batch_interval = batch_interval
        self.interface = interface

        self.packets = []
        self.lock = threading.Lock()
        self.stop_monitoring = threading.Event()
        self.monitor_thread = None
        self.batch_thread = None
        self.socket = None

        # Statistics
        self.last_batch_time = datetime.now()
        self.total_packets_collected = 0

        logger.info(
            f"Network traffic collector initialized with batch size: {max_packets}, interval: {batch_interval}s")

    def start(self):
        """Start network traffic monitoring"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            logger.warning("Network traffic collector already running")
            return

        try:
            # Create raw socket for packet capture
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

            if self.interface:
                self.socket.bind((self.interface, 0))

            self.stop_monitoring.clear()

            # Start monitoring thread
            self.monitor_thread = threading.Thread(target=self._monitor_traffic)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

            # Start batch sender thread
            self.batch_thread = threading.Thread(target=self._batch_sender)
            self.batch_thread.daemon = True
            self.batch_thread.start()

            logger.info("Network traffic monitoring started with improved batching")

        except PermissionError:
            logger.error("Permission denied: Raw socket requires root privileges")
            return False
        except Exception as e:
            logger.error(f"Error starting network monitoring: {str(e)}")
            return False

        return True

    def stop(self):
        """Stop network traffic monitoring"""
        self.stop_monitoring.set()

        # Send any remaining packets before stopping
        self._send_remaining_packets()

        if self.socket:
            self.socket.close()

        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)

        if self.batch_thread and self.batch_thread.is_alive():
            self.batch_thread.join(timeout=2)

        logger.info("Network traffic monitoring stopped")

    def _monitor_traffic(self):
        """Monitor network traffic and collect packets"""
        logger.info("Starting packet capture")

        while not self.stop_monitoring.is_set():
            try:
                # Set socket timeout to allow periodic checking of stop_monitoring
                self.socket.settimeout(1.0)

                try:
                    # Receive packet
                    packet, addr = self.socket.recvfrom(65535)

                    # Parse the packet
                    parsed_packet = self._parse_packet(packet)
                    if parsed_packet:
                        with self.lock:
                            self.packets.append(parsed_packet)
                            self.total_packets_collected += 1

                        # Check if we've reached max_packets
                        with self.lock:
                            if len(self.packets) >= self.max_packets:
                                self._send_batch()

                except socket.timeout:
                    # Timeout is expected, continue monitoring
                    continue
                except Exception as e:
                    if not self.stop_monitoring.is_set():
                        logger.error(f"Error receiving packet: {str(e)}")
                    break

            except Exception as e:
                logger.error(f"Error in traffic monitoring: {str(e)}")
                time.sleep(1)

        logger.info("Packet capture stopped")

    def _batch_sender(self):
        """Send batches based on time interval"""
        while not self.stop_monitoring.is_set():
            try:
                time.sleep(self.batch_interval)

                with self.lock:
                    if self.packets:
                        self._send_batch()

            except Exception as e:
                logger.error(f"Error in batch sender: {str(e)}")

    def _send_batch(self):
        """Send the current batch of packets"""
        if not self.packets:
            return

        # Prepare batch data
        batch_data = {
            'timestamp': datetime.now().isoformat(),
            'packets': self.packets.copy(),
            'stats': self._calculate_stats(self.packets),
            'batch_info': {
                'packet_count': len(self.packets),
                'time_span': (datetime.now() - self.last_batch_time).total_seconds(),
                'total_collected': self.total_packets_collected
            }
        }

        # Clear the packets buffer
        self.packets.clear()
        self.last_batch_time = datetime.now()

        # Send via callback
        if self.callback:
            logger.info(f"Sending network batch with {len(batch_data['packets'])} packets")
            success = self.callback(batch_data)
            if not success:
                logger.warning("Callback returned False, batch sending failed")

    def _send_remaining_packets(self):
        """Send any remaining packets in the buffer before shutdown"""
        with self.lock:
            if self.packets:
                self._send_batch()

    def _calculate_stats(self, packets):
        """Calculate statistics for the packet batch"""
        stats = {
            'total_packets': len(packets),
            'protocols': {},
            'traffic_volume': 0,
            'unique_ips': set(),
            'ports': set()
        }

        for packet in packets:
            # Count protocols
            protocol = packet.get('protocol', 'unknown')
            stats['protocols'][protocol] = stats['protocols'].get(protocol, 0) + 1

            # Sum traffic volume
            stats['traffic_volume'] += packet.get('size', 0)

            # Collect unique IPs and ports
            if packet.get('from'):
                stats['unique_ips'].add(packet['from'])
            if packet.get('to'):
                stats['unique_ips'].add(packet['to'])
            if packet.get('src_port'):
                stats['ports'].add(packet['src_port'])
            if packet.get('dst_port'):
                stats['ports'].add(packet['dst_port'])

        # Convert sets to counts for JSON serialization
        stats['unique_ip_count'] = len(stats['unique_ips'])
        stats['unique_port_count'] = len(stats['ports'])
        del stats['unique_ips']  # Remove set objects
        del stats['ports']

        return stats

    def _parse_packet(self, packet):
        """Parse a raw network packet

        Args:
            packet (bytes): Raw packet data

        Returns:
            dict: Parsed packet information or None if parsing fails
        """
        try:
            # Parse Ethernet header (14 bytes)
            if len(packet) < 14:
                return None

            eth_header = struct.unpack('!6s6sH', packet[:14])
            eth_protocol = socket.ntohs(eth_header[2])

            # We're mainly interested in IP packets
            if eth_protocol != 0x0800:  # IPv4
                return None

            # Parse IP header
            if len(packet) < 34:  # Ethernet + IP header minimum
                return None

            ip_header = packet[14:34]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4

            protocol = iph[6]
            src_addr = socket.inet_ntoa(iph[8])
            dst_addr = socket.inet_ntoa(iph[9])

            # Parse transport layer for ports
            src_port = None
            dst_port = None

            if protocol == 6:  # TCP
                protocol_name = 'TCP'
                if len(packet) >= 14 + iph_length + 4:
                    tcp_header = packet[14 + iph_length:14 + iph_length + 4]
                    tcph = struct.unpack('!HH', tcp_header)
                    src_port = tcph[0]
                    dst_port = tcph[1]
            elif protocol == 17:  # UDP
                protocol_name = 'UDP'
                if len(packet) >= 14 + iph_length + 4:
                    udp_header = packet[14 + iph_length:14 + iph_length + 4]
                    udph = struct.unpack('!HH', udp_header)
                    src_port = udph[0]
                    dst_port = udph[1]
            elif protocol == 1:  # ICMP
                protocol_name = 'ICMP'
            else:
                protocol_name = f'Other({protocol})'

            return {
                'from': src_addr,
                'to': dst_addr,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol_name,
                'size': len(packet),
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.debug(f"Error parsing packet: {str(e)}")
            return None

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

    def get_stats(self):
        """Get current collection statistics

        Returns:
            dict: Statistics about packet collection
        """
        with self.lock:
            return {
                'buffer_size': len(self.packets),
                'total_collected': self.total_packets_collected,
                'last_batch_time': self.last_batch_time.isoformat(),
                'monitoring_active': not self.stop_monitoring.is_set()
            }