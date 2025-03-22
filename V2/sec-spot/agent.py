#!/usr/bin/env python3
# agent.py - Main entry point for the sec-spot agent

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
from analyzers.metrics_analyzer import MetricsAnalyzer
from analyzers.security_analyzer import SecurityAnalyzer
from utils.logger import setup_logging

# Setup logging
logger = setup_logging()

# Load environment variables from config.env
dotenv.load_dotenv('/usr/sec-spot/config.env')

class Agent:
    """Main agent class that orchestrates all monitoring components"""
    
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
            
            # Initialize collectors
            self.system_collector = SystemMetricsCollector()
            self.network_collector = NetworkTrafficCollector(
                callback=self.on_network_data_collected,
                max_packets=50
            )
            self.security_collector = SecurityCollector(
                callback=self.on_security_events_collected,
                check_interval= self.settings.MONITORING_INTERVAL  # 5 minutes
            )
            self.log_collector = LogCollector(
                callback=self.on_logs_collected,
                check_interval= self.settings.MONITORING_INTERVAL  # 2 minutes
            )
            
            # Initialize analyzers
            self.metrics_analyzer = MetricsAnalyzer()
            self.security_analyzer = SecurityAnalyzer()
            
            # Last data collection timestamps
            self.last_metrics_time = 0
            self.last_security_time = 0
            
            # Flags
            self.running = False
            self.shutdown_requested = False
            
            logger.info(f"Agent initialized with server ID: {self.settings.SERVER_ID}")
        
        except Exception as e:
            logger.error(f"Error initializing agent: {str(e)}")
            raise
    
    def start(self):
        """Start the agent and all its components"""
        try:
            logger.info("Starting sec-spot agent")
            
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
        """Main execution loop"""
        if not self.start():
            return
        
        try:
            while self.running and not self.shutdown_requested:
                current_time = time.time()
                
                # Collect and analyze system metrics
                if current_time - self.last_metrics_time >= self.settings.MONITORING_INTERVAL:
                    self.collect_and_analyze_metrics()
                    self.last_metrics_time = current_time
                
                # Sleep a short time to prevent CPU hogging
                time.sleep(1)
        
        except KeyboardInterrupt:
            logger.info("Agent stopping due to keyboard interrupt")
        except Exception as e:
            logger.error(f"Error in main loop: {str(e)}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the agent and clean up resources"""
        logger.info("Stopping agent")
        self.running = False
        
        # Stop collectors
        self.network_collector.stop()
        self.security_collector.stop()
        self.log_collector.stop()
        
        # Close connections
        self.ws_client.disconnect()
        
        logger.info("Agent stopped")
    
    def _register_signal_handlers(self):
        """Register signal handlers for clean shutdown"""
        import signal
        
        def signal_handler(sig, frame):
            logger.info(f"Received signal {sig}, initiating shutdown")
            self.shutdown_requested = True
        
        # Register for SIGTERM and SIGINT
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
    
    def collect_and_analyze_metrics(self):
        """Collect and analyze system metrics"""
        try:
            # Collect system metrics
            metrics = self.system_collector.collect()
            if not metrics:
                logger.warning("Failed to collect system metrics")
                return
            
            # Analyze metrics for anomalies
            analysis = self.metrics_analyzer.analyze(metrics)
            
            # Send metrics to server
            success = self.ws_client.send_message('agent.resource-monitoring', [metrics])
            if success:
                logger.info("System metrics sent successfully")
            else:
                logger.error("Failed to send system metrics")
            
            # If anomalies detected, send alert
            if analysis.get('has_anomalies', False):
                alert_data = {
                    "alert_type": "anomaly",
                    "anomalies": analysis.get('anomalies', []),
                    "timestamp": datetime.now().isoformat()
                }
                
                success = self.ws_client.send_message('agent.alert', alert_data)
                if success:
                    logger.info(f"Sent alert for {len(analysis['anomalies'])} anomalies")
                else:
                    logger.error("Failed to send anomaly alert")
        
        except Exception as e:
            logger.error(f"Error in metrics collection and analysis: {str(e)}")
    
    def on_network_data_collected(self, network_data):
        """Callback when network data is collected"""
        if not network_data:
            return True
        
        try:
            success = self.ws_client.send_message('agent.network-traffic', network_data)
            if success:
                logger.info(f"Network traffic data sent successfully ({len(network_data)} packets)")
                return True
            else:
                logger.error("Failed to send network traffic data")
                return False
        except Exception as e:
            logger.error(f"Error processing network data: {str(e)}")
            return False
    
    def on_security_events_collected(self, security_events):
        """Callback when security events are collected"""
        if not security_events:
            return True
        
        try:
            # Analyze security events for threats
            analysis = self.security_analyzer.analyze(security_events)
            
            # Send security data to server
            security_data = {
                "events": security_events,
                "analysis": analysis
            }
            
            success = self.ws_client.send_message('agent.security-events', security_data)
            if success:
                logger.info("Security events sent successfully")
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
    
    def on_logs_collected(self, log_entries):
        """Callback when logs are collected"""
        if not log_entries or not log_entries.get('entries'):
            return True
        
        try:
            # Only send logs with errors or warnings, or if specifically configured
            if (log_entries.get('has_errors', False) or 
                log_entries.get('has_warnings', False) or 
                self.settings.SEND_ALL_LOGS):
                
                success = self.ws_client.send_message('agent.logs', log_entries)
                if success:
                    logger.info(f"Log entries sent successfully ({len(log_entries['entries'])} entries)")
                else:
                    logger.error("Failed to send log entries")
                
                # If there are errors, send an alert
                if log_entries.get('has_errors', False):
                    error_entries = [e for e in log_entries['entries'] if e['severity'] == 'error']
                    
                    alert_data = {
                        "alert_type": "log",
                        "errors": error_entries[:10],  # First 10 errors
                        "error_count": len(error_entries),
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    success = self.ws_client.send_message('agent.alert', alert_data)
                    if success:
                        logger.info(f"Sent alert for {len(error_entries)} log errors")
                    else:
                        logger.error("Failed to send log alert")
                
                return success
            
            return True
        
        except Exception as e:
            logger.error(f"Error processing log entries: {str(e)}")
            return False


if __name__ == "__main__":
    agent = Agent()
    agent.run()