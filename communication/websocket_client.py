 
# communication/websocket_client.py
import json
import logging
import threading
import time
import ssl
import socket
import platform
from datetime import datetime
import websocket

logger = logging.getLogger('sec-spot-agent.websocket')

class WebSocketClient:
    """Client for WebSocket communication with the server"""
    
    def __init__(self, uri, server_id,channel,agent_version, retries=3):
        """Initialize WebSocket client
        
        Args:
            uri (str): WebSocket server URI
            server_id (str): Server ID for identification
            agent_version (str): Agent version
            retries (int): Number of connection retries
        """
        self.uri = uri
        self.server_id = server_id
        self.agent_version = agent_version
        self.max_retries = retries

        self.channel = channel

        self.ws = None
        self.connected = False
        self.retry_count = 0
        self.reconnect_delay = 5  # seconds
        
        # System info for identification
        self.hostname = socket.gethostname()
        self.platform = platform.system()
        self.platform_version = platform.version()
    
    def connect(self):
        """Establish WebSocket connection with retry logic
        
        Returns:
            bool: True if connection was established, False otherwise
        """
        while self.retry_count < self.max_retries and not self.connected:
            try:
                logger.info(f"Connecting to WebSocket at {self.uri}")
                self.ws = websocket.WebSocketApp(
                    self.uri,
                    on_open=self._on_open,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close
                )
                
                # Start WebSocket connection in a separate thread
                ws_thread = threading.Thread(target=self.ws.run_forever, kwargs={
                    'sslopt': {"cert_reqs": ssl.CERT_NONE} if self.uri.startswith('wss') else {},
                    'ping_interval': 30,
                    'ping_timeout': 10
                })
                ws_thread.daemon = True
                ws_thread.start()
                
                # Wait for connection to be established
                for _ in range(5):
                    if self.connected:
                        break
                    time.sleep(1)
                
                if self.connected:
                    logger.info("WebSocket connection established")
                    self.retry_count = 0
                    return True
                else:
                    logger.warning("Failed to connect to WebSocket, retrying...")
                    self.retry_count += 1
                    time.sleep(self.reconnect_delay)
            
            except Exception as e:
                logger.error(f"WebSocket connection error: {str(e)}")
                self.retry_count += 1
                time.sleep(self.reconnect_delay)
        
        if not self.connected:
            logger.error(f"Failed to connect to WebSocket after {self.max_retries} attempts")
            return False
        
        return True
    
    def disconnect(self):
        """Close the WebSocket connection"""
        if self.ws:
            self.ws.close()
            logger.info("WebSocket connection closed")
    
    def _on_open(self, ws):
        """Called when WebSocket connection is opened"""
        self.connected = True
        logger.info("WebSocket connection established")
    
    def _on_message(self, ws, message):
        """Handle incoming WebSocket messages"""
        try:
            data = json.loads(message)
            logger.info(f"Received message: {data.get('event', 'unknown')}")
            
            # Handle any commands from the server
            if data.get('event') == 'command':
                self._handle_command(data)
        except Exception as e:
            logger.error(f"Error processing message: {str(e)}")
    
    def _on_error(self, ws, error):
        """Handle WebSocket errors"""
        logger.error(f"WebSocket error: {str(error)}")
        self.connected = False
    
    def _on_close(self, ws, close_status_code, close_msg):
        """Handle WebSocket connection closure"""
        logger.info(f"WebSocket connection closed: {close_status_code} - {close_msg}")
        self.connected = False
        
        # Try to reconnect
        if self.retry_count < self.max_retries:
            logger.info("Attempting to reconnect...")
            time.sleep(self.reconnect_delay)
            self.connect()
    
    def _handle_command(self, data):
        """Handle commands received from the server"""
        command = data.get('command')
        
        if command == 'restart':
            logger.info("Received restart command")
            # Implement restart logic
        elif command == 'update':
            logger.info("Received update command")
            # Implement update logic
        else:
            logger.warning(f"Unknown command: {command}")
    
    def send_message(self, event, data):
        """Send a message over WebSocket
        
        Args:
            event (str): Event name
            data (dict): Data to send
            
        Returns:
            bool: True if message was sent successfully, False otherwise
        """
        if not self.connected:
            logger.warning("WebSocket not connected, attempting to reconnect")
            if not self.connect():
                logger.error("Failed to reconnect WebSocket, message not sent")
                return False
        
        try:
            message = {
                'event': event,
                'server_id': self.server_id,
                'channel': self.channel,
                'agent_version': self.agent_version,
                'data': data
            }
            
            self.ws.send(json.dumps(message))
            return True
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")
            self.connected = False
            return False
    
    def send_subscribe_message(self):
        """Send subscription message to identify this agent"""
        try:
            message = {
                'event': 'agent.subscribe',
                'channel':self.channel,
                'server_id': self.server_id,
                'agent_version': self.agent_version,
                'hostname': self.hostname,
                'platform': self.platform,
                'platform_version': self.platform_version,
                'timestamp': datetime.now().isoformat(),
                'data':[{'event': 'agent.subscribe'}]
            }
            
            self.ws.send(json.dumps(message))
            logger.info("Subscribe message sent")
            return True
        except Exception as e:
            logger.error(f"Error sending subscribe message: {str(e)}")
            self.connected = False
            return False