# utils/helpers.py
import os
import json
import socket
import platform
import subprocess
import logging
from datetime import datetime

logger = logging.getLogger('sec-spot-agent.helpers')

def get_system_info():
    """Get basic system information
    
    Returns:
        dict: System information
    """
    try:
        info = {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'platform_version': platform.version(),
            'platform_release': platform.release(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'timestamp': datetime.now().isoformat()
        }
        
        # Get more detailed Linux information if available
        if platform.system() == 'Linux':
            try:
                # Get distribution info
                if os.path.exists('/etc/os-release'):
                    with open('/etc/os-release', 'r') as f:
                        os_release = {}
                        for line in f:
                            if '=' in line:
                                key, value = line.strip().split('=', 1)
                                os_release[key] = value.strip('"')
                        
                        if 'NAME' in os_release:
                            info['distribution'] = os_release['NAME']
                        if 'VERSION_ID' in os_release:
                            info['distribution_version'] = os_release['VERSION_ID']
                
                # Get kernel version
                result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
                if result.returncode == 0:
                    info['kernel_version'] = result.stdout.strip()
            except Exception as e:
                logger.warning(f"Error getting detailed Linux info: {str(e)}")
        
        return info
    
    except Exception as e:
        logger.error(f"Error getting system info: {str(e)}")
        return {
            'hostname': 'unknown',
            'platform': 'unknown',
            'timestamp': datetime.now().isoformat()
        }

def bytes_to_human_readable(bytes_value):
    """Convert bytes to human-readable form
    
    Args:
        bytes_value (int): Number of bytes
        
    Returns:
        str: Human-readable string
    """
    try:
        bytes_value = int(bytes_value)
    except (TypeError, ValueError):
        return "0 B"
    
    if bytes_value < 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    unit_index = 0
    
    while bytes_value >= 1024 and unit_index < len(units) - 1:
        bytes_value /= 1024.0
        unit_index += 1
    
    return f"{bytes_value:.2f} {units[unit_index]}"

def is_valid_json(json_str):
    """Check if a string is valid JSON
    
    Args:
        json_str (str): JSON string to validate
        
    Returns:
        bool: True if valid JSON, False otherwise
    """
    try:
        json.loads(json_str)
        return True
    except (json.JSONDecodeError, TypeError):
        return False

def run_command(command):
    """Run a shell command and get the output
    
    Args:
        command (str or list): Command to run
        
    Returns:
        tuple: (success, output, error)
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=isinstance(command, str)
        )
        
        return (
            result.returncode == 0,
            result.stdout.strip(),
            result.stderr.strip()
        )
    
    except Exception as e:
        logger.error(f"Error running command {command}: {str(e)}")
        return False, "", str(e)

def is_port_open(host, port, timeout=2):
    """Check if a port is open on a host
    
    Args:
        host (str): Host to check
        port (int): Port to check
        timeout (int, optional): Connection timeout in seconds
        
    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_file_hash(file_path, hash_type='sha256'):
    """Get a file's hash
    
    Args:
        file_path (str): Path to file
        hash_type (str, optional): Hash type ('md5', 'sha1', 'sha256')
        
    Returns:
        str: File hash or None on error
    """
    try:
        import hashlib
        
        if not os.path.isfile(file_path):
            return None
        
        hash_func = getattr(hashlib, hash_type)()
        
        with open(file_path, 'rb') as f:
            # Read in 64k chunks
            for chunk in iter(lambda: f.read(65536), b''):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    except Exception as e:
        logger.error(f"Error getting file hash: {str(e)}")
        return None