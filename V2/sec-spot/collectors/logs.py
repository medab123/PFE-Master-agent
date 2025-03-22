# collectors/logs.py
import logging
import os
import re
import threading
import time
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger('sec-spot-agent.logs')

class LogCollector:
    """Collector for system logs and application logs"""
    
    def __init__(self, callback=None, check_interval=60):
        """Initialize the log collector
        
        Args:
            callback (callable): Function to call when logs are collected
            check_interval (int): Interval between log checks in seconds
        """
        self.callback = callback
        self.check_interval = check_interval
        self.stop_collecting = threading.Event()
        self.collector_thread = None
        
        # Common log files to monitor
        self.log_files = [
            {'path': '/var/log/syslog', 'type': 'system'},
            {'path': '/var/log/auth.log', 'type': 'auth'},
            {'path': '/var/log/secure', 'type': 'auth'},
            {'path': '/var/log/apache2/access.log', 'type': 'web'},
            {'path': '/var/log/apache2/error.log', 'type': 'web'},
            {'path': '/var/log/nginx/access.log', 'type': 'web'},
            {'path': '/var/log/nginx/error.log', 'type': 'web'},
            {'path': '/var/log/mysql/error.log', 'type': 'database'},
            {'path': '/var/log/postgresql/postgresql.log', 'type': 'database'},
        ]
        
        # Filter to existing log files only
        self.log_files = [log for log in self.log_files if os.path.exists(log['path'])]
        
        # Last read positions for each log file
        self.log_positions = {log['path']: 0 for log in self.log_files}
        
        # Log patterns to classify importance
        self.log_patterns = {
            'error': [
                r'\berror\b',
                r'\bfail(ed|ure)\b',
                r'\bcritical\b',
                r'\bemergency\b',
                r'\balert\b'
            ],
            'warning': [
                r'\bwarn(ing)?\b',
                r'\bnotice\b',
                r'\btimeout\b'
            ],
            'info': [
                r'\binfo\b',
                r'\bstarted\b',
                r'\bstopped\b',
                r'\bcompleted\b'
            ]
        }
        
        logger.info(f"Log collector initialized with {len(self.log_files)} log files")
    
    def start(self):
        """Start log collection in a separate thread"""
        self.stop_collecting.clear()
        self.collector_thread = threading.Thread(target=self._collect_logs)
        self.collector_thread.daemon = True
        self.collector_thread.start()
        logger.info("Log collection started")
    
    def stop(self):
        """Stop log collection"""
        self.stop_collecting.set()
        if self.collector_thread and self.collector_thread.is_alive():
            self.collector_thread.join(timeout=2)
        logger.info("Log collection stopped")
    
    def _collect_logs(self):
        """Main collection loop for logs"""
        try:
            # Initial read of log files to set starting positions
            for log_file in self.log_files:
                try:
                    with open(log_file['path'], 'r') as f:
                        f.seek(0, os.SEEK_END)
                        self.log_positions[log_file['path']] = f.tell()
                except Exception as e:
                    logger.error(f"Error reading log file {log_file['path']}: {str(e)}")
            
            # Collection loop
            while not self.stop_collecting.is_set():
                # Collect logs
                log_entries = self.collect()
                
                # If entries collected and callback provided, call it
                if log_entries and self.callback:
                    self.callback(log_entries)
                
                # Sleep until next check
                self.stop_collecting.wait(self.check_interval)
        
        except Exception as e:
            logger.error(f"Error in log collection: {str(e)}")
    
    def collect(self):
        """Collect new log entries from monitored files
        
        Returns:
            dict: Dictionary with collected log entries
        """
        collected_entries = {
            'timestamp': datetime.now().isoformat(),
            'entries': []
        }
        
        # Keep track of log statistics
        log_stats = {
            'total': 0,
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int)
        }
        
        for log_file in self.log_files:
            if not os.path.exists(log_file['path']):
                continue
                
            try:
                with open(log_file['path'], 'r') as f:
                    # Start from last read position
                    f.seek(self.log_positions[log_file['path']])
                    
                    # Read new lines
                    new_lines = f.readlines()
                    
                    # Update position
                    self.log_positions[log_file['path']] = f.tell()
                    
                    # Process each line
                    for line in new_lines:
                        severity = self._determine_severity(line)
                        log_stats['total'] += 1
                        log_stats['by_type'][log_file['type']] += 1
                        log_stats['by_severity'][severity] += 1
                        
                        collected_entries['entries'].append({
                            'file': log_file['path'],
                            'type': log_file['type'],
                            'severity': severity,
                            'content': line.strip()
                        })
            
            except Exception as e:
                logger.error(f"Error reading log file {log_file['path']}: {str(e)}")
        
        # Add statistics to collected entries
        collected_entries['stats'] = log_stats
        
        # Determine if collection contains important logs
        has_errors = log_stats['by_severity']['error'] > 0
        has_warnings = log_stats['by_severity']['warning'] > 0
        
        collected_entries['has_errors'] = has_errors
        collected_entries['has_warnings'] = has_warnings
        collected_entries['importance'] = 'high' if has_errors else ('medium' if has_warnings else 'low')
        
        if log_stats['total'] > 0:
            logger.info(f"Collected {log_stats['total']} log entries")
        
        return collected_entries if log_stats['total'] > 0 else None
    
    def _determine_severity(self, log_line):
        """Determine the severity of a log line
        
        Args:
            log_line (str): Log line to analyze
            
        Returns:
            str: Severity level (error, warning, info)
        """
        log_line = log_line.lower()
        
        # Check for error patterns
        for pattern in self.log_patterns['error']:
            if re.search(pattern, log_line):
                return 'error'
        
        # Check for warning patterns
        for pattern in self.log_patterns['warning']:
            if re.search(pattern, log_line):
                return 'warning'
        
        # Check for info patterns
        for pattern in self.log_patterns['info']:
            if re.search(pattern, log_line):
                return 'info'
        
        # Default to info
        return 'info'