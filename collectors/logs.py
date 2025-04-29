# collectors/logs.py
import logging
import os
import re
import threading
import time
from datetime import datetime
from collections import defaultdict
import queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger('sec-spot-agent.logs')

class LogCollector:
    """Collector for system logs and application logs using real-time monitoring"""
    
    def __init__(self, callback=None, check_interval=60):
        """Initialize the log collector
        
        Args:
            callback (callable): Function to call when logs are collected
            check_interval (int): Interval between log checks in seconds (fallback)
        """
        self.callback = callback
        self.check_interval = check_interval
        self.stop_collecting = threading.Event()
        self.collector_thread = None
        self.monitor_thread = None
        self.log_queue = queue.Queue()
        self.observer = None
        
        # Common log files to monitor
        self.log_files = [
            # System logs
            {'path': '/var/log/syslog', 'type': 'system'},
            {'path': '/var/log/messages', 'type': 'system'},
            {'path': '/var/log/dmesg', 'type': 'system'},

            # Authentication logs
            {'path': '/var/log/auth.log', 'type': 'auth'},
            {'path': '/var/log/secure', 'type': 'auth'},
            {'path': '/var/log/faillog', 'type': 'auth'},

            # Web server logs
            {'path': '/var/log/apache2/access.log', 'type': 'web'},
            {'path': '/var/log/apache2/error.log', 'type': 'web'},
            {'path': '/var/log/nginx/access.log', 'type': 'web'},
            {'path': '/var/log/nginx/error.log', 'type': 'web'},

            # Database logs
            {'path': '/var/log/mysql/error.log', 'type': 'database'},
            {'path': '/var/log/mysql/mysql.log', 'type': 'database'},
            {'path': '/var/log/postgresql/postgresql.log', 'type': 'database'},

            # Docker
            {'path': '/var/log/docker.log', 'type': 'container'},

            # Cron
            {'path': '/var/log/cron', 'type': 'scheduler'},
            {'path': '/var/log/cron.log', 'type': 'scheduler'},

            # Mail services
            {'path': '/var/log/mail.log', 'type': 'mail'},
            {'path': '/var/log/mail.err', 'type': 'mail'},

            # Kernel
            {'path': '/var/log/kern.log', 'type': 'kernel'},

            # Firewall
            {'path': '/var/log/ufw.log', 'type': 'firewall'},
            {'path': '/var/log/firewalld', 'type': 'firewall'},

            # Application-specific (optional based on use)
            {'path': '/var/log/php7.4-fpm.log', 'type': 'app'},
            {'path': '/var/log/php8.1-fpm.log', 'type': 'app'},
            {'path': '/var/log/redis/redis-server.log', 'type': 'database'},
            {'path': '/var/log/elasticsearch/elasticsearch.log', 'type': 'search'},
            {'path': '/var/log/rsync.log', 'type': 'sync'},
        ]
        
        # Filter to existing log files only
        self.log_files = [log for log in self.log_files if os.path.exists(log['path'])]
        
        # Create a mapping from file path to file metadata
        self.file_metadata = {log['path']: log for log in self.log_files}
        
        # Last read positions for each log file
        self.log_positions = {log['path']: 0 for log in self.log_files}
        
        # Time of last batch send
        self.last_batch_time = datetime.now()
        
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
        """Start log collection using real-time file monitoring"""
        if self.collector_thread and self.collector_thread.is_alive():
            logger.warning("Log collector already running")
            return
        
        self.stop_collecting.clear()
        
        # Initialize log positions
        self._initialize_log_positions()
        
        # Start the monitor thread
        self.monitor_thread = threading.Thread(target=self._monitor_log_files)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Start the processing thread
        self.collector_thread = threading.Thread(target=self._process_log_queue)
        self.collector_thread.daemon = True
        self.collector_thread.start()
        
        logger.info("Log collection started with real-time monitoring")
    
    def stop(self):
        """Stop log collection"""
        self.stop_collecting.set()
        
        # Stop the observer if it's running
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=2)
        
        if self.collector_thread and self.collector_thread.is_alive():
            self.collector_thread.join(timeout=2)
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
            
        logger.info("Log collection stopped")
    
    def _initialize_log_positions(self):
        """Initialize the file positions to start reading from the end of each file"""
        for log_file in self.log_files:
            try:
                with open(log_file['path'], 'r') as f:
                    f.seek(0, os.SEEK_END)
                    self.log_positions[log_file['path']] = f.tell()
            except Exception as e:
                logger.error(f"Error reading log file {log_file['path']}: {str(e)}")
    
    def _monitor_log_files(self):
        """Monitor log files for changes using watchdog"""
        try:
            # Create a file event handler
            class LogEventHandler(FileSystemEventHandler):
                def __init__(self, collector):
                    self.collector = collector
                
                def on_modified(self, event):
                    if not event.is_directory and event.src_path in self.collector.file_metadata:
                        self.collector.log_queue.put(event.src_path)
            
            # Create the event handler
            event_handler = LogEventHandler(self)
            
            # Create the observer
            self.observer = Observer()
            
            # Get unique directories to watch
            watched_dirs = set()
            for log_file in self.log_files:
                watched_dirs.add(os.path.dirname(log_file['path']))
            
            # Schedule the observer to watch each directory
            for directory in watched_dirs:
                try:
                    self.observer.schedule(event_handler, directory, recursive=False)
                except Exception as e:
                    logger.error(f"Error scheduling watch for directory {directory}: {str(e)}")
            
            # Start the observer
            self.observer.start()
            logger.info("Watchdog observer started")
            
            # Keep the thread alive until stop_collecting is set
            while not self.stop_collecting.is_set():
                time.sleep(1)
            
            # Observer will be stopped in the stop() method
            logger.info("Watchdog monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error in file monitoring: {str(e)}")
            # Fall back to polling method
            logger.info("Falling back to polling method")
            self._collect_logs_polling()
    
    def _process_log_queue(self):
        """Process the queue of modified log files"""
        batch_interval = 10  # Batch logs every 10 seconds
        collected_entries = {
            'timestamp': datetime.now().isoformat(),
            'entries': [],
            'stats': {
                'total': 0,
                'by_type': defaultdict(int),
                'by_severity': defaultdict(int)
            }
        }
        
        while not self.stop_collecting.is_set():
            try:
                # Get all unique log files that were modified in the last batch interval
                modified_files = set()
                
                # Try to get a file from the queue, with timeout
                try:
                    file_path = self.log_queue.get(timeout=1)
                    modified_files.add(file_path)
                    self.log_queue.task_done()
                except queue.Empty:
                    pass
                
                # Get any additional files in the queue (without blocking)
                while not self.log_queue.empty():
                    try:
                        file_path = self.log_queue.get_nowait()
                        modified_files.add(file_path)
                        self.log_queue.task_done()
                    except queue.Empty:
                        break
                
                # Read new content from each modified file
                for file_path in modified_files:
                    file_info = self.file_metadata.get(file_path)
                    if not file_info:
                        continue
                    
                    self._read_new_content(file_path, file_info, collected_entries)
                
                # Check if it's time to send a batch
                current_time = datetime.now()
                time_since_last_batch = (current_time - self.last_batch_time).total_seconds()
                
                if (time_since_last_batch >= batch_interval and collected_entries['entries']) or len(collected_entries['entries']) > 100:
                    # Set flags based on content
                    has_errors = collected_entries['stats']['by_severity']['error'] > 0
                    has_warnings = collected_entries['stats']['by_severity']['warning'] > 0
                    
                    collected_entries['has_errors'] = has_errors
                    collected_entries['has_warnings'] = has_warnings
                    collected_entries['importance'] = 'high' if has_errors else ('medium' if has_warnings else 'low')
                    
                    # If we have entries and a callback, send them
                    if collected_entries['entries'] and self.callback:
                        logger.info(f"Sending {len(collected_entries['entries'])} log entries")
                        self.callback(collected_entries)
                    
                    # Reset for next batch
                    collected_entries = {
                        'timestamp': current_time.isoformat(),
                        'entries': [],
                        'stats': {
                            'total': 0,
                            'by_type': defaultdict(int),
                            'by_severity': defaultdict(int)
                        }
                    }
                    self.last_batch_time = current_time
                
                # Sleep a short time to prevent CPU hogging
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error processing log queue: {str(e)}")
                time.sleep(1)  # Sleep longer on error
    
    def _read_new_content(self, file_path, file_info, collected_entries):
        """Read new content from a log file and add to entries"""
        try:
            with open(file_path, 'r') as f:
                # Start from last read position
                f.seek(self.log_positions[file_path])
                
                # Read new lines
                new_lines = f.readlines()
                
                # Update position
                self.log_positions[file_path] = f.tell()
                
                # Process each line
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                        
                    severity = self._determine_severity(line)
                    collected_entries['stats']['total'] += 1
                    collected_entries['stats']['by_type'][file_info['type']] += 1
                    collected_entries['stats']['by_severity'][severity] += 1
                    
                    collected_entries['entries'].append({
                        'file': file_path,
                        'type': file_info['type'],
                        'severity': severity,
                        'content': line
                    })
        
        except Exception as e:
            logger.error(f"Error reading log file {file_path}: {str(e)}")
    
    def _collect_logs_polling(self):
        """Fallback method that polls log files periodically"""
        logger.info("Using polling method for log collection")
        
        while not self.stop_collecting.is_set():
            try:
                # Put all log files in the queue to be processed
                for log_file in self.log_files:
                    self.log_queue.put(log_file['path'])
                
                # Wait until next check
                self.stop_collecting.wait(self.check_interval)
                
            except Exception as e:
                logger.error(f"Error in polling log collection: {str(e)}")
                time.sleep(5)  # Sleep longer on error
    
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
        
        # Default to N/A
        return 'N/A'
    
    def collect(self):
        """Manual collection method (for compatibility)
        
        Returns:
            dict: Dictionary with collected log entries, or None if no new entries
        """
        # Put all log files in the queue to be processed
        for log_file in self.log_files:
            self.log_queue.put(log_file['path'])
        
        # This will just trigger processing, actual collection is done in _process_log_queue
        return None
