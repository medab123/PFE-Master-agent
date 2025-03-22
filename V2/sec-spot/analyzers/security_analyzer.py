# analyzers/security_analyzer.py
import logging
import re
import time
from collections import defaultdict, Counter

logger = logging.getLogger('sec-spot-agent.analyzer.security')

class SecurityAnalyzer:
    """Analyzer for security events to detect threats"""
    
    def __init__(self, ip_threshold=5, auth_threshold=3, scan_threshold=10):
        """Initialize the security analyzer
        
        Args:
            ip_threshold (int): Threshold for suspicious activities from same IP
            auth_threshold (int): Threshold for authentication failures
            scan_threshold (int): Threshold for port scanning detection
        """
        self.ip_threshold = ip_threshold
        self.auth_threshold = auth_threshold
        self.scan_threshold = scan_threshold
        
        # Tracking data structures
        self.ip_activity = defaultdict(int)  # IP -> activity count
        self.auth_failures = defaultdict(int)  # User -> failure count
        self.port_scans = defaultdict(set)  # IP -> set of ports
        
        # Time windows (in seconds)
        self.ip_window = 3600  # 1 hour
        self.auth_window = 300  # 5 minutes
        self.scan_window = 60   # 1 minute
        
        # Timestamps for cleanup
        self.last_ip_cleanup = time.time()
        self.last_auth_cleanup = time.time()
        self.last_scan_cleanup = time.time()
        
        logger.info("Security analyzer initialized")
    
    def analyze(self, security_events):
        """Analyze security events for threats
        
        Args:
            security_events (dict): Security events to analyze
            
        Returns:
            dict: Analysis results with detected threats
        """
        # Perform cleanup of old data
        self._cleanup_old_data()
        
        # Process suspicious logins
        auth_threats = self._analyze_auth_events(security_events.get('suspicious_logins', []))
        
        # Process network connections and open ports
        network_threats = self._analyze_network_events(
            security_events.get('active_connections', []),
            security_events.get('open_ports', [])
        )
        
        # Process suspicious processes
        process_threats = self._analyze_process_events(security_events.get('suspicious_processes', []))
        
        # Combine all threats
        all_threats = auth_threats + network_threats + process_threats
        
        return {
            "threats": all_threats,
            "has_threats": len(all_threats) > 0,
            "num_threats": len(all_threats),
            "analysis_time": time.time()
        }
    
    def _analyze_auth_events(self, auth_events):
        """Analyze authentication events for threats
        
        Args:
            auth_events (list): Authentication events to analyze
            
        Returns:
            list: Detected authentication threats
        """
        threats = []
        
        # Extract IPs and usernames from auth events
        ip_pattern = r'from\s+(\d+\.\d+\.\d+\.\d+)'
        user_pattern = r'(?:user|for|USER)\s+(\w+)'
        
        for event in auth_events:
            entry = event.get('entry', '')
            
            # Extract IP address
            ip_match = re.search(ip_pattern, entry)
            if ip_match:
                ip = ip_match.group(1)
                self.ip_activity[ip] += 1
                
                # Check if IP exceeds threshold
                if self.ip_activity[ip] >= self.ip_threshold:
                    threats.append({
                        'type': 'brute_force_ip',
                        'ip': ip,
                        'count': self.ip_activity[ip],
                        'threshold': self.ip_threshold,
                        'description': f'Possible brute force attack from IP {ip}'
                    })
            
            # Extract username
            user_match = re.search(user_pattern, entry)
            if user_match:
                username = user_match.group(1)
                
                # Ignore system usernames
                if username not in ('root', 'nobody', 'daemon'):
                    self.auth_failures[username] += 1
                    
                    # Check if username exceeds threshold
                    if self.auth_failures[username] >= self.auth_threshold:
                        threats.append({
                            'type': 'brute_force_user',
                            'username': username,
                            'count': self.auth_failures[username],
                            'threshold': self.auth_threshold,
                            'description': f'Possible brute force attack targeting user {username}'
                        })
        
        return threats
    
    def _analyze_network_events(self, connections, open_ports):
        """Analyze network events for threats
        
        Args:
            connections (list): Active connections to analyze
            open_ports (list): Open ports to analyze
            
        Returns:
            list: Detected network threats
        """
        threats = []
        
        # Detect port scanning
        for conn in connections:
            remote_ip = conn.get('remote_ip')
            if remote_ip:
                # Extract port from remote address
                port_match = re.search(r':(\d+)$', conn.get('local', ''))
                if port_match:
                    port = int(port_match.group(1))
                    self.port_scans[remote_ip].add(port)
                    
                    # Check for port scanning (many ports in short time)
                    if len(self.port_scans[remote_ip]) >= self.scan_threshold:
                        threats.append({
                            'type': 'port_scan',
                            'ip': remote_ip,
                            'ports': list(self.port_scans[remote_ip]),
                            'count': len(self.port_scans[remote_ip]),
                            'threshold': self.scan_threshold,
                            'description': f'Possible port scanning from IP {remote_ip}'
                        })
        
        # TODO: Add more network threat detection logic
        # For example, detecting connections to suspicious IPs/ports
        
        return threats
    
    def _analyze_process_events(self, process_events):
        """Analyze process events for threats
        
        Args:
            process_events (list): Process events to analyze
            
        Returns:
            list: Detected process threats
        """
        threats = []
        
        # TODO: Implement process threat detection
        # This could involve detecting known malicious process patterns
        # or processes with suspicious characteristics
        
        return threats
    
    def _cleanup_old_data(self):
        """Clean up old data based on time windows"""
        current_time = time.time()
        
        # Clean up IP activity data
        if current_time - self.last_ip_cleanup > self.ip_window:
            self.ip_activity.clear()
            self.last_ip_cleanup = current_time
        
        # Clean up auth failure data
        if current_time - self.last_auth_cleanup > self.auth_window:
            self.auth_failures.clear()
            self.last_auth_cleanup = current_time
        
        # Clean up port scan data
        if current_time - self.last_scan_cleanup > self.scan_window:
            self.port_scans.clear()
            self.last_scan_cleanup = current_time