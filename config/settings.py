 
# config/settings.py
import os
import socket
import platform

class Settings:
    """Configuration settings for the agent, loaded from environment variables"""
    
    def __init__(self):
        """Load settings from environment variables with defaults"""
        self.SERVER_ID = os.getenv('SERVER_ID')
        self.REVERB_URI = os.getenv('REVERB_URI')
        self.REVERB_CHANNEL = os.getenv('REVERB_CHANNEL')
        self.AGENT_VERSION = os.getenv('AGENT_VERSION', '2.0.0')
        self.MONITORING_INTERVAL = int(os.getenv('MONITORING_INTERVAL', '20'))  # seconds
        self.RETRIES = int(os.getenv('RETRIES', '3'))
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
        self.SEND_ALL_LOGS = os.getenv('LOG_LEVEL', False),
        
        # System information
        self.HOSTNAME = socket.gethostname()
        self.PLATFORM = platform.system()
        self.PLATFORM_VERSION = platform.version()
        
        # Validate essential settings
        self._validate_settings()
    
    def _validate_settings(self):
        """Validate that all required settings are present"""
        if not self.SERVER_ID:
            raise ValueError("SERVER_ID environment variable is required")
        
        if not self.REVERB_URI:
            raise ValueError("REVERB_URI environment variable is required")
        
        if not self.REVERB_CHANNEL:
            raise ValueError("REVERB_CHANNEL environment variable is required")