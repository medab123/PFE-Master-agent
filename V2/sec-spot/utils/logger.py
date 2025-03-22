# utils/logger.py
import os
import logging
import logging.handlers
from datetime import datetime

def setup_logging(log_level=None, log_file=None):
    """Set up logging configuration
    
    Args:
        log_level (str, optional): Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file (str, optional): Path to log file
        
    Returns:
        logging.Logger: Configured logger
    """
    # Get log level from environment or use default
    if log_level is None:
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    # Get log file from environment or use default
    if log_file is None:
        log_file = os.getenv('LOG_FILE', '/var/log/sec-spot-agent.log')
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except Exception:
            # If we can't create the directory, use a default location
            log_file = '/tmp/sec-spot-agent.log'
    
    # Set up root logger
    root_logger = logging.getLogger()
    
    # Clear any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Set log level
    numeric_level = getattr(logging, log_level, None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
    root_logger.setLevel(numeric_level)
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Create file handler with rotation
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10 MB
            backupCount=5
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    except (IOError, PermissionError) as e:
        # If we can't write to the log file, at least print a message
        print(f"Warning: Could not create log file at {log_file}: {e}")
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # Create agent logger
    logger = logging.getLogger('sec-spot-agent')
    
    # Log startup info
    logger.info(f"Logging initialized at level {log_level}")
    logger.info(f"Log file: {log_file}")
    
    return logger

class LoggerAdapter(logging.LoggerAdapter):
    """Adapter to add context information to log records"""
    
    def __init__(self, logger, prefix="", extra=None):
        """Initialize the adapter
        
        Args:
            logger (logging.Logger): Logger to adapt
            prefix (str, optional): Prefix to add to log messages
            extra (dict, optional): Extra context to add to log records
        """
        super().__init__(logger, extra or {})
        self.prefix = prefix
    
    def process(self, msg, kwargs):
        """Process the log message with context information
        
        Args:
            msg (str): Log message
            kwargs (dict): Keyword arguments
            
        Returns:
            tuple: (modified_message, modified_kwargs)
        """
        if self.prefix:
            msg = f"{self.prefix}: {msg}"
        
        return msg, kwargs

def get_module_logger(module_name):
    """Get a logger for a specific module
    
    Args:
        module_name (str): Name of the module
        
    Returns:
        LoggerAdapter: Logger with module context
    """
    logger = logging.getLogger(f'sec-spot-agent.{module_name}')
    return LoggerAdapter(logger, module_name)