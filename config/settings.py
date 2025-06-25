# config/settings.py - Updated with batch configuration options
import os
import logging

logger = logging.getLogger('sec-spot-agent.config')


class Settings:
    """Configuration settings for the sec-spot agent with batch support"""

    def __init__(self):
        """Initialize settings from environment variables"""

        # Agent identification
        self.AGENT_VERSION = os.getenv('AGENT_VERSION', '1.0.0')
        self.SERVER_ID = self._get_required_env('SERVER_ID')

        # Server connection
        self.API_BASE_URL = self._get_required_env('API_BASE_URL')
        self.REVERB_URI = self._get_required_env('REVERB_URI')
        self.REVERB_CHANNEL = self._get_required_env('REVERB_CHANNEL')

        # Monitoring settings
        self.MONITORING_INTERVAL = int(os.getenv('MONITORING_INTERVAL', '60'))
        self.RETRIES = int(os.getenv('RETRIES', '3'))

        # Logging settings
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
        self.LOG_FILE = os.getenv('LOG_FILE', '/var/log/sec-spot-agent.log')

        # Security settings
        self.SEND_ALL_LOGS = os.getenv('SEND_ALL_LOGS', 'false').lower() == 'true'

        # Network monitoring settings
        self.MONITOR_NETWORK_TRAFFIC = os.getenv('MONITOR_NETWORK_TRAFFIC', 'true').lower() == 'true'
        self.NETWORK_BATCH_SIZE = int(os.getenv('NETWORK_BATCH_SIZE', '1000'))
        self.NETWORK_BATCH_INTERVAL = int(os.getenv('NETWORK_BATCH_INTERVAL', '60'))

        # Log collection batching settings
        self.LOG_BATCH_SIZE = int(os.getenv('LOG_BATCH_SIZE', '500'))
        self.LOG_BATCH_INTERVAL = int(os.getenv('LOG_BATCH_INTERVAL', '30'))

        # Security monitoring settings
        self.SECURITY_CHECK_INTERVAL = int(os.getenv('SECURITY_CHECK_INTERVAL', '300'))

        # Advanced batching settings (for future features)
        self.ENABLE_COMPRESSION = os.getenv('ENABLE_COMPRESSION', 'false').lower() == 'true'
        self.MAX_BATCH_MEMORY = os.getenv('MAX_BATCH_MEMORY', '50MB')
        self.BATCH_PRIORITY = os.getenv('BATCH_PRIORITY', 'normal').lower()

        # Validate settings
        self._validate_settings()

        # Log configuration
        logger.info("Settings loaded successfully")
        logger.info(f"Network batching: {self.NETWORK_BATCH_SIZE} packets / {self.NETWORK_BATCH_INTERVAL}s")
        logger.info(f"Log batching: {self.LOG_BATCH_SIZE} entries / {self.LOG_BATCH_INTERVAL}s")

    def _get_required_env(self, var_name):
        """Get a required environment variable or raise an error"""
        value = os.getenv(var_name)
        if not value:
            raise ValueError(f"Required environment variable {var_name} is not set")
        return value

    def _validate_settings(self):
        """Validate configuration settings"""

        # Validate batch sizes
        if self.NETWORK_BATCH_SIZE <= 0:
            raise ValueError("NETWORK_BATCH_SIZE must be greater than 0")

        if self.LOG_BATCH_SIZE <= 0:
            raise ValueError("LOG_BATCH_SIZE must be greater than 0")

        # Validate batch intervals
        if self.NETWORK_BATCH_INTERVAL <= 0:
            raise ValueError("NETWORK_BATCH_INTERVAL must be greater than 0")

        if self.LOG_BATCH_INTERVAL <= 0:
            raise ValueError("LOG_BATCH_INTERVAL must be greater than 0")

        # Validate monitoring intervals
        if self.MONITORING_INTERVAL <= 0:
            raise ValueError("MONITORING_INTERVAL must be greater than 0")

        if self.SECURITY_CHECK_INTERVAL <= 0:
            raise ValueError("SECURITY_CHECK_INTERVAL must be greater than 0")

        # Validate retry count
        if self.RETRIES < 0:
            raise ValueError("RETRIES must be 0 or greater")

        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.LOG_LEVEL not in valid_log_levels:
            raise ValueError(f"LOG_LEVEL must be one of: {', '.join(valid_log_levels)}")

        # Validate batch priority (for future use)
        valid_priorities = ['low', 'normal', 'high']
        if self.BATCH_PRIORITY not in valid_priorities:
            logger.warning(f"Invalid BATCH_PRIORITY '{self.BATCH_PRIORITY}', using 'normal'")
            self.BATCH_PRIORITY = 'normal'

        # Warn about potentially large batch sizes
        if self.NETWORK_BATCH_SIZE > 5000:
            logger.warning(f"Large network batch size ({self.NETWORK_BATCH_SIZE}) may impact memory usage")

        if self.LOG_BATCH_SIZE > 2000:
            logger.warning(f"Large log batch size ({self.LOG_BATCH_SIZE}) may impact memory usage")

        # Warn about very short intervals
        if self.NETWORK_BATCH_INTERVAL < 10:
            logger.warning(f"Very short network batch interval ({self.NETWORK_BATCH_INTERVAL}s) may impact performance")

        if self.LOG_BATCH_INTERVAL < 5:
            logger.warning(f"Very short log batch interval ({self.LOG_BATCH_INTERVAL}s) may impact performance")

    def get_batch_config(self):
        """Get batch configuration as a dictionary"""
        return {
            'network': {
                'batch_size': self.NETWORK_BATCH_SIZE,
                'batch_interval': self.NETWORK_BATCH_INTERVAL
            },
            'logs': {
                'batch_size': self.LOG_BATCH_SIZE,
                'batch_interval': self.LOG_BATCH_INTERVAL
            },
            'advanced': {
                'enable_compression': self.ENABLE_COMPRESSION,
                'max_batch_memory': self.MAX_BATCH_MEMORY,
                'batch_priority': self.BATCH_PRIORITY
            }
        }

    def update_batch_config(self, config_type, **kwargs):
        """Update batch configuration dynamically

        Args:
            config_type (str): 'network' or 'logs'
            **kwargs: Configuration parameters to update
        """
        if config_type == 'network':
            if 'batch_size' in kwargs:
                self.NETWORK_BATCH_SIZE = int(kwargs['batch_size'])
            if 'batch_interval' in kwargs:
                self.NETWORK_BATCH_INTERVAL = int(kwargs['batch_interval'])
        elif config_type == 'logs':
            if 'batch_size' in kwargs:
                self.LOG_BATCH_SIZE = int(kwargs['batch_size'])
            if 'batch_interval' in kwargs:
                self.LOG_BATCH_INTERVAL = int(kwargs['batch_interval'])
        else:
            raise ValueError("config_type must be 'network' or 'logs'")

        # Re-validate after update
        self._validate_settings()

        logger.info(f"Updated {config_type} batch configuration: {kwargs}")

    def __str__(self):
        """String representation of settings (excluding sensitive data)"""
        return f"""Settings:
  Agent Version: {self.AGENT_VERSION}
  Server ID: {self.SERVER_ID}
  Monitoring Interval: {self.MONITORING_INTERVAL}s
  Network Batching: {self.NETWORK_BATCH_SIZE} packets / {self.NETWORK_BATCH_INTERVAL}s
  Log Batching: {self.LOG_BATCH_SIZE} entries / {self.LOG_BATCH_INTERVAL}s
  Log Level: {self.LOG_LEVEL}
  Send All Logs: {self.SEND_ALL_LOGS}"""