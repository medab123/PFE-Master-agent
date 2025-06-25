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
    """Collector for system logs and application logs using real-time monitoring with improved batching"""

    def __init__(self, callback=None, check_interval=60, exclude_logs=None, batch_size=500, batch_interval=30):
        """Initialize the log collector

        Args:
            callback (callable): Function to call when logs are collected
            check_interval (int): Interval between log checks in seconds (fallback)
            exclude_logs (list): List of log files to exclude from monitoring
            batch_size (int): Maximum number of entries per batch (default: 500)
            batch_interval (int): Maximum time between batches in seconds (default: 30)
        """
        self.callback = callback
        self.check_interval = check_interval
        self.batch_size = batch_size
        self.batch_interval = batch_interval
        self.stop_collecting = threading.Event()
        self.collector_thread = None
        self.monitor_thread = None
        self.log_queue = queue.Queue()
        self.observer = None

        # List of log files to exclude from monitoring
        self.exclude_logs = exclude_logs or [
            '/var/log/sec-spot.log',
            '/var/log/sec-spot-agent.log',
        ]

        # Dynamically discover all files in /var/log
        self.log_files = []
        self._discover_log_files('/var/log')

        # Create a mapping from file path to file metadata
        self.file_metadata = {log['path']: log for log in self.log_files}

        # Last read positions for each log file
        self.log_positions = {log['path']: 0 for log in self.log_files}

        # Time of last batch send
        self.last_batch_time = datetime.now()

        # Accumulated log entries buffer
        self.log_buffer = []
        self.buffer_lock = threading.Lock()

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
        logger.info(f"Batch size: {self.batch_size}, Batch interval: {self.batch_interval}s")

    def _discover_log_files(self, root_dir):
        """Discover log files in the given directory"""
        try:
            for root, dirs, files in os.walk(root_dir):
                for file in files:
                    path = os.path.join(root, file)

                    # Skip excluded files
                    if path in self.exclude_logs:
                        continue

                    # Check if it's a log file
                    if self._is_log_file(path):
                        try:
                            file_info = {
                                'path': path,
                                'type': self._get_log_type(path),
                                'size': os.path.getsize(path),
                                'modified': os.path.getmtime(path)
                            }
                            self.log_files.append(file_info)
                        except (OSError, PermissionError) as e:
                            logger.warning(f"Cannot access file {path}: {str(e)}")
        except PermissionError:
            logger.warning(f"Permission denied for {root_dir}")
        except Exception as e:
            logger.error(f"Error scanning directory {root_dir}: {str(e)}")

    def _is_log_file(self, path):
        """Check if a file is a log file"""
        log_extensions = ['.log', '.out', '.err']
        log_names = ['syslog', 'messages', 'auth.log', 'secure', 'kern.log', 'mail.log']

        filename = os.path.basename(path)

        # Check extensions
        if any(path.endswith(ext) for ext in log_extensions):
            return True

        # Check common log file names
        if any(name in filename for name in log_names):
            return True

        return False

    def _get_log_type(self, path):
        """Determine the type of log file"""
        filename = os.path.basename(path).lower()

        if 'auth' in filename or 'secure' in filename:
            return 'auth'
        elif 'kern' in filename:
            return 'kernel'
        elif 'mail' in filename:
            return 'mail'
        elif 'apache' in filename or 'nginx' in filename or 'httpd' in filename:
            return 'web'
        elif 'mysql' in filename or 'postgres' in filename:
            return 'database'
        else:
            return 'system'

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

        # Start the batch sender thread
        self.batch_thread = threading.Thread(target=self._batch_sender)
        self.batch_thread.daemon = True
        self.batch_thread.start()

        logger.info("Log collection started with improved batching")

    def stop(self):
        """Stop log collection"""
        self.stop_collecting.set()

        # Send any remaining logs before stopping
        self._send_remaining_logs()

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

            logger.info("Watchdog monitoring stopped")

        except Exception as e:
            logger.error(f"Error in file monitoring: {str(e)}")
            logger.info("Falling back to polling method")
            self._collect_logs_polling()

    def _process_log_queue(self):
        """Process the queue of modified log files and add to buffer"""
        while not self.stop_collecting.is_set():
            try:
                modified_files = set()

                # Get files from queue with timeout
                try:
                    file_path = self.log_queue.get(timeout=1)
                    modified_files.add(file_path)
                    self.log_queue.task_done()
                except queue.Empty:
                    continue

                # Get any additional files in the queue (without blocking)
                while not self.log_queue.empty():
                    try:
                        file_path = self.log_queue.get_nowait()
                        modified_files.add(file_path)
                        self.log_queue.task_done()
                    except queue.Empty:
                        break

                # Read new content from each modified file
                new_entries = []
                for file_path in modified_files:
                    file_info = self.file_metadata.get(file_path)
                    if not file_info:
                        continue

                    entries = self._read_new_content(file_path, file_info)
                    new_entries.extend(entries)

                # Add new entries to buffer
                if new_entries:
                    with self.buffer_lock:
                        self.log_buffer.extend(new_entries)
                        logger.debug(f"Added {len(new_entries)} entries to buffer. Buffer size: {len(self.log_buffer)}")

                # Check if buffer is full
                with self.buffer_lock:
                    if len(self.log_buffer) >= self.batch_size:
                        self._send_batch()

                time.sleep(0.1)

            except Exception as e:
                logger.error(f"Error processing log queue: {str(e)}")
                time.sleep(1)

    def _batch_sender(self):
        """Send batches based on time interval"""
        while not self.stop_collecting.is_set():
            try:
                time.sleep(self.batch_interval)

                with self.buffer_lock:
                    if self.log_buffer:
                        self._send_batch()

            except Exception as e:
                logger.error(f"Error in batch sender: {str(e)}")

    def _send_batch(self):
        """Send the current batch of log entries"""
        if not self.log_buffer:
            return

        # Prepare batch data
        batch_data = {
            'timestamp': datetime.now().isoformat(),
            'entries': self.log_buffer.copy(),
            'stats': self._calculate_stats(self.log_buffer)
        }

        # Clear the buffer
        self.log_buffer.clear()
        self.last_batch_time = datetime.now()

        # Send via callback
        if self.callback:
            logger.info(f"Sending batch with {len(batch_data['entries'])} log entries")
            self.callback(batch_data)

    def _send_remaining_logs(self):
        """Send any remaining logs in the buffer before shutdown"""
        with self.buffer_lock:
            if self.log_buffer:
                self._send_batch()

    def _calculate_stats(self, entries):
        """Calculate statistics for the batch"""
        stats = {
            'total': len(entries),
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int)
        }

        for entry in entries:
            stats['by_type'][entry['type']] += 1
            stats['by_severity'][entry['severity']] += 1

        return dict(stats)

    def _read_new_content(self, file_path, file_info):
        """Read new content from a log file and return entries"""
        entries = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
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
                    entries.append({
                        'file': file_path,
                        'type': file_info['type'],
                        'severity': severity,
                        'content': line,
                        'timestamp': datetime.now().isoformat()
                    })

        except Exception as e:
            logger.error(f"Error reading log file {file_path}: {str(e)}")

        return entries

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
                time.sleep(5)

    def _determine_severity(self, log_line):
        """Determine the severity of a log line"""
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

        return 'info'  # Default to info level