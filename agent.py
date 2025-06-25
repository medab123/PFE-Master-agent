#!/usr/bin/env python3
# agent.py - Main entry point for the sec-spot agent with improved batching

import os
import time
import logging
import threading
import json
import dotenv
from datetime import datetime

# Import components
from config.settings import Settings
from communication.websocket_client import WebSocketClient
from collectors.system_metrics import SystemMetricsCollector
from collectors.network_traffic import NetworkTrafficCollector
from collectors.security import SecurityCollector
from collectors.logs import LogCollector
from analyzers.security_analyzer import SecurityAnalyzer
from utils.logger import setup_logging

# Setup logging
logger = setup_logging()

# Load environment variables from config.env
dotenv.load_dotenv('/usr/sec-spot/config.env')


class Agent:
    """Main agent class that orchestrates all monitoring components with improved batching"""

    def __init__(self):
        """Initialize the agent and its components"""
        try:
            # Load settings
            self.settings = Settings()

            # Initialize the WebSocket client
            self.ws_client = WebSocketClient(
                uri=self.settings.REVERB_URI,
                server_id=self.settings.SERVER_ID,
                channel=self.settings.REVERB_CHANNEL,
                agent_version=self.settings.AGENT_VERSION,
                retries=self.settings.RETRIES
            )

            # Initialize collectors with improved batching
            self.system_collector = SystemMetricsCollector()

            # Network collector with larger batches and longer intervals
            self.network_collector = NetworkTrafficCollector(
                callback=self.on_network_data_collected,
                max_packets=1000,  # Increased from 50
                batch_interval=60  # Increased from immediate sending
            )

            # Security collector with batching
            self.security_collector = SecurityCollector(
                callback=self.on_security_events_collected,
                check_interval=self.settings.MONITORING_INTERVAL
            )

            # Log collector with improved batching
            self.log_collector = LogCollector(
                callback=self.on_logs_collected,
                check_interval=self.settings.MONITORING_INTERVAL,
                batch_size=500,  # Increased from 100
                batch_interval=30  # Increased from 10
            )

            # Initialize analyzers
            self.security_analyzer = SecurityAnalyzer()

            # Last data collection timestamps
            self.last_metrics_time = 0
            self.last_security_time = 0

            # Flags
            self.running = False
            self.shutdown_requested = False

            # Batch statistics
            self.batch_stats = {
                'logs_sent': 0,
                'network_batches_sent': 0,
                'security_batches_sent': 0,
                'total_log_entries': 0,
                'total_packets': 0
            }

            logger.info(f"Agent initialized with server ID: {self.settings.SERVER_ID}")
            logger.info("Improved batching enabled: Logs(500/30s), Network(1000/60s)")

        except Exception as e:
            logger.error(f"Error initializing agent: {str(e)}")
            raise

    def start(self):
        """Start the agent and all its components"""
        try:
            logger.info("Starting sec-spot agent with improved batching")

            # Connect to WebSocket
            if not self.ws_client.connect():
                logger.error("Failed to establish WebSocket connection, exiting")
                return False

            # Send initial subscription message
            self.ws_client.send_subscribe_message()

            # Start collectors
            self.network_collector.start()
            self.security_collector.start()
            self.log_collector.start()

            self.running = True

            # Register signal handlers for clean shutdown
            self._register_signal_handlers()

            return True

        except Exception as e:
            logger.error(f"Error starting agent: {str(e)}")
            return False

    def run(self):
        """Main agent loop"""
        try:
            # Start all components
            if not self.start():
                return

            # Main monitoring loop
            while self.running and not self.shutdown_requested:
                try:
                    current_time = time.time()

                    # Collect system metrics at specified intervals
                    if current_time - self.last_metrics_time >= self.settings.MONITORING_INTERVAL:
                        self._collect_and_send_metrics()
                        self.last_metrics_time = current_time

                    # Log batch statistics periodically
                    if int(current_time) % 300 == 0:  # Every 5 minutes
                        self._log_batch_statistics()

                    # Sleep to prevent high CPU usage
                    time.sleep(1)

                except KeyboardInterrupt:
                    logger.info("Received keyboard interrupt, shutting down gracefully")
                    break
                except Exception as e:
                    logger.error(f"Error in main loop: {str(e)}")
                    time.sleep(5)

        finally:
            self.stop()

    def stop(self):
        """Stop the agent and clean up resources"""
        logger.info("Stopping sec-spot agent")

        self.running = False
        self.shutdown_requested = True

        # Stop collectors (they will send remaining batches)
        if hasattr(self, 'network_collector'):
            self.network_collector.stop()

        if hasattr(self, 'security_collector'):
            self.security_collector.stop()

        if hasattr(self, 'log_collector'):
            self.log_collector.stop()

        # Close WebSocket connection
        if hasattr(self, 'ws_client'):
            self.ws_client.disconnect()

        # Log final statistics
        self._log_batch_statistics()

        logger.info("Agent stopped successfully")

    def _collect_and_send_metrics(self):
        """Collect and send system metrics"""
        try:
            metrics = self.system_collector.collect()
            if metrics:
                success = self.ws_client.send_message('agent.metrics', metrics)
                if success:
                    logger.debug("System metrics sent successfully")
                else:
                    logger.error("Failed to send system metrics")

        except Exception as e:
            logger.error(f"Error collecting system metrics: {str(e)}")

    def on_network_data_collected(self, network_batch):
        """Callback when network data batch is collected

        Args:
            network_batch (dict): Batch of network packets with metadata
        """
        if not network_batch or not network_batch.get('packets'):
            return True

        try:
            # Update statistics
            self.batch_stats['network_batches_sent'] += 1
            self.batch_stats['total_packets'] += len(network_batch['packets'])

            # Send the batch
            success = self.ws_client.send_message('agent.network-traffic', network_batch)
            if success:
                packet_count = len(network_batch['packets'])
                traffic_volume = network_batch['stats'].get('traffic_volume', 0)
                logger.info(f"Network batch sent: {packet_count} packets, {traffic_volume} bytes")
            else:
                logger.error("Failed to send network traffic batch")

            return success

        except Exception as e:
            logger.error(f"Error processing network data batch: {str(e)}")
            return False

    def on_security_events_collected(self, security_events):
        """Callback when security events are collected"""
        if not security_events:
            return True

        try:
            # Analyze security events
            analysis = self.security_analyzer.analyze(security_events)

            # Prepare security data with analysis
            security_data = {
                "events": security_events,
                "analysis": analysis,
                "timestamp": datetime.now().isoformat()
            }

            # Update statistics
            self.batch_stats['security_batches_sent'] += 1

            # Send the security data
            success = self.ws_client.send_message('agent.security-events', security_data)
            if success:
                logger.info(f"Security events sent: {len(security_events)} events")
            else:
                logger.error("Failed to send security events")

            # If threats detected, send alert
            if analysis.get('has_threats', False):
                alert_data = {
                    "alert_type": "security",
                    "threats": analysis.get('threats', []),
                    "timestamp": datetime.now().isoformat()
                }

                success = self.ws_client.send_message('agent.alert', alert_data)
                if success:
                    logger.info(f"Sent alert for {len(analysis['threats'])} security threats")
                else:
                    logger.error("Failed to send security alert")

            return success

        except Exception as e:
            logger.error(f"Error processing security events: {str(e)}")
            return False

    def on_logs_collected(self, log_batch):
        """Callback when log batch is collected

        Args:
            log_batch (dict): Batch of log entries with metadata
        """
        if not log_batch or not log_batch.get('entries'):
            return True

        try:
            # Update statistics
            self.batch_stats['logs_sent'] += 1
            self.batch_stats['total_log_entries'] += len(log_batch['entries'])

            # Send the batch
            success = self.ws_client.send_message('agent.logs', log_batch)
            if success:
                entry_count = len(log_batch['entries'])
                stats = log_batch.get('stats', {})
                error_count = stats.get('by_severity', {}).get('error', 0)
                warning_count = stats.get('by_severity', {}).get('warning', 0)

                logger.info(f"Log batch sent: {entry_count} entries "
                            f"(errors: {error_count}, warnings: {warning_count})")
            else:
                logger.error("Failed to send log batch")

            return success

        except Exception as e:
            logger.error(f"Error processing log batch: {str(e)}")
            return False

    def _log_batch_statistics(self):
        """Log current batch statistics"""
        stats = self.batch_stats.copy()

        # Add current buffer sizes
        if hasattr(self, 'log_collector'):
            with self.log_collector.buffer_lock:
                stats['current_log_buffer'] = len(self.log_collector.log_buffer)

        if hasattr(self, 'network_collector'):
            with self.network_collector.lock:
                stats['current_network_buffer'] = len(self.network_collector.packets)

        logger.info(f"Batch Statistics: {json.dumps(stats, indent=2)}")

    def _register_signal_handlers(self):
        """Register signal handlers for graceful shutdown"""
        import signal

        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown")
            self.shutdown_requested = True

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)


if __name__ == "__main__":
    agent = Agent()
    agent.run()