 
# collectors/system_metrics.py
import logging
import psutil
from datetime import datetime

logger = logging.getLogger('sec-spot-agent.system')

class SystemMetricsCollector:
    """Collector for system metrics like CPU, RAM, and disk usage"""
    
    def __init__(self):
        """Initialize the system metrics collector"""
        logger.info("System metrics collector initialized")
    
    def collect(self):
        """Collect system metrics
        
        Returns:
            dict: Collected metrics or None on error
        """
        try:
            # CPU usage (percentage)
            cpu_usage = psutil.cpu_percent(interval=1)
            
            # Memory information
            memory = psutil.virtual_memory()
            ram_total = memory.total
            ram_used = memory.used
            
            # Disk information (root partition)
            disk = psutil.disk_usage('/')
            rom_total = disk.total
            rom_used = disk.used
            
            # Network information
            net_io = psutil.net_io_counters()
            bytes_sent = net_io.bytes_sent
            bytes_recv = net_io.bytes_recv
            packets_sent = net_io.packets_sent
            packets_recv = net_io.packets_recv
            
            # Additional metrics
            load_avg = psutil.getloadavg()  # 1, 5, and 15 minute load averages
            uptime = int(datetime.now().timestamp() - psutil.boot_time())
            
            metrics = {
                'cpu_usage_percent': cpu_usage,
                'ram_total': ram_total,
                'ram_used': ram_used,
                'rom_total': rom_total,
                'rom_used': rom_used,
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_recv,
                'packets_sent': packets_sent,
                'packets_received': packets_recv,
                'load_avg_1m': load_avg[0],
                'load_avg_5m': load_avg[1],
                'load_avg_15m': load_avg[2],
                'uptime_seconds': uptime,
                'timestamp': datetime.now().isoformat()
            }
            
            # Disk partitions information (additional detail)
            disk_partitions = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_partitions.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    })
                except (PermissionError, OSError):
                    # Some mountpoints might not be accessible
                    pass
            
            # Add disk partitions to metrics if needed
            # Uncomment if you want to include detailed partition info
            # metrics['disk_partitions'] = disk_partitions
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {str(e)}")
            return None
    
    def get_process_info(self, top_n=10):
        """Get information about top processes by CPU usage
        
        Args:
            top_n (int): Number of top processes to retrieve
            
        Returns:
            list: List of process information dictionaries
        """
        try:
            processes = []
            for proc in sorted(psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']), 
                              key=lambda p: p.info['cpu_percent'] or 0, 
                              reverse=True)[:top_n]:
                try:
                    proc_info = proc.info
                    proc_info['created_time'] = datetime.fromtimestamp(proc.create_time()).isoformat()
                    processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return processes
        except Exception as e:
            logger.error(f"Error collecting process information: {str(e)}")
            return []