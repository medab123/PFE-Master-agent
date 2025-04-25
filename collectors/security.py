# collectors/security.py
import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime

logger = logging.getLogger('sec-spot-agent.security')

class SecurityCollector:
    """Collector for security-related information and events"""
    
    def __init__(self, callback=None, check_interval=300):
        """Initialize the security collector
        
        Args:
            callback (callable): Function to call when security events are detected
            check_interval (int): Interval between security checks in seconds
        """
        self.callback = callback
        self.check_interval = check_interval
        self.stop_monitoring = threading.Event()
        self.monitor_thread = None
        
        # Common security log files to monitor
        self.log_files = [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/syslog',
            '/var/log/messages'
        ]
        
        # Filter to existing log files only
        self.log_files = [f for f in self.log_files if os.path.exists(f)]
        
        # Last read positions for each log file
        self.log_positions = {file: 0 for file in self.log_files}
        
        # Patterns to detect in logs (common attack patterns)
        self.suspicious_patterns = [
            r'Failed password for .* from',
            r'Invalid user .* from',
            r'authentication failure',
            r'POSSIBLE BREAK-IN ATTEMPT',
            r'refused connect from',
            r'pam_unix\(sshd:auth\): authentication failure'
        ]
        
        logger.info("Security collector initialized")
    
    def start(self):
        """Start security monitoring in a separate thread"""
        self.stop_monitoring.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_security)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logger.info("Security monitoring started")
    
    def stop(self):
        """Stop security monitoring"""
        self.stop_monitoring.set()
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
        logger.info("Security monitoring stopped")
    
    def _monitor_security(self):
        """Main monitoring loop for security events"""
        try:
            # Initial read of log files to set starting positions
            for log_file in self.log_files:
                try:
                    with open(log_file, 'r') as f:
                        f.seek(0, os.SEEK_END)
                        self.log_positions[log_file] = f.tell()
                except Exception as e:
                    logger.error(f"Error reading log file {log_file}: {str(e)}")
            
            # Monitor loop
            while not self.stop_monitoring.is_set():
                # Check for suspicious activities
                security_events = self.check_security()
                
                # If events detected and callback provided, call it
                if security_events and self.callback:
                    self.callback(security_events)
                
                # Sleep until next check
                self.stop_monitoring.wait(self.check_interval)
        
        except Exception as e:
            logger.error(f"Error in security monitoring: {str(e)}")
    
    def check_security(self):
        """Check for security issues
        
        Returns:
            dict: Dictionary with security events and findings
        """
        security_events = {
            'timestamp': datetime.now().isoformat(),
            'suspicious_logins': self._check_auth_logs(),
            'open_ports': self._check_open_ports(),
            'active_connections': self._check_active_connections(),
            'suspicious_processes': self._check_suspicious_processes()
        }
        
        # Count total suspicious events
        total_suspicious = sum(len(events) for events in security_events.values() if isinstance(events, list))
        security_events['total_suspicious'] = total_suspicious
        
        if total_suspicious > 0:
            logger.warning(f"Detected {total_suspicious} suspicious security events")
        
        return security_events
    
    def _check_auth_logs(self):
        """Check authentication logs for suspicious activities
        
        Returns:
            list: List of suspicious log entries
        """
        suspicious_entries = []
        
        for log_file in self.log_files:
            if not os.path.exists(log_file):
                continue
                
            try:
                with open(log_file, 'r') as f:
                    # Start from last read position
                    f.seek(self.log_positions[log_file])
                    
                    # Read new lines
                    new_lines = f.readlines()
                    
                    # Update position
                    self.log_positions[log_file] = f.tell()
                    
                    # Check each line for suspicious patterns
                    for line in new_lines:
                        for pattern in self.suspicious_patterns:
                            if re.search(pattern, line):
                                suspicious_entries.append({
                                    'log_file': log_file,
                                    'entry': line.strip(),
                                    'pattern': pattern
                                })
                                break
            except Exception as e:
                logger.error(f"Error reading log file {log_file}: {str(e)}")
        
        return suspicious_entries
    
    def _check_open_ports(self):
        """Check for open network ports
        
        Returns:
            list: List of open ports with process information
        """
        try:
            # Use netstat to get open ports (requires net-tools package)
            output = subprocess.check_output(['netstat', '-tulpn'], stderr=subprocess.STDOUT, text=True)
            
            # Parse output to extract port information
            open_ports = []
            for line in output.splitlines():
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 7:
                        address = parts[3]
                        program = parts[6].split('/')[1] if '/' in parts[6] else parts[6]
                        
                        # Extract port number
                        port = address.split(':')[-1]
                        
                        open_ports.append({
                            'port': port,
                            'address': address,
                            'program': program
                        })
            
            return open_ports
        except Exception as e:
            logger.error(f"Error checking open ports: {str(e)}")
            return []
    
    def _check_active_connections(self):
        """Check for active network connections
        
        Returns:
            list: List of active connections that look suspicious
        """
        try:
            # Use netstat to get established connections
            output = subprocess.check_output(['netstat', '-tn'], stderr=subprocess.STDOUT, text=True)
            
            connections = []
            suspicious_connections = []
            
            # Parse output to extract connection information
            for line in output.splitlines():
                if 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        local_address = parts[3]
                        remote_address = parts[4]
                        
                        # Extract remote IP
                        remote_ip = remote_address.split(':')[0]
                        
                        connections.append({
                            'local': local_address,
                            'remote': remote_address,
                            'remote_ip': remote_ip
                        })
            
            # TODO: Add logic to identify suspicious connections
            # This could involve checking against known bad IP lists
            # or detecting unusual connection patterns
            
            return suspicious_connections
        except Exception as e:
            logger.error(f"Error checking active connections: {str(e)}")
            return []
    
    def _check_suspicious_processes(self):
        """Check for suspicious processes
        
        Returns:
            list: List of potentially suspicious processes
        """
        try:
            # Get process listing
            output = subprocess.check_output(['ps', 'aux'], stderr=subprocess.STDOUT, text=True)
            
            suspicious_processes = []
            
            # TODO: Add logic to identify suspicious processes
            # This could involve checking for known malicious process names
            # or detecting processes with unusual characteristics
            
            return suspicious_processes
        except Exception as e:
            logger.error(f"Error checking suspicious processes: {str(e)}")
            return []