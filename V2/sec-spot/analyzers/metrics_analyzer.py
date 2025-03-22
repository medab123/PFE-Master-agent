# analyzers/metrics_analyzer.py
import logging
import time
from collections import deque

logger = logging.getLogger('sec-spot-agent.analyzer.metrics')

class MetricsAnalyzer:
    """Analyzer for system metrics to detect anomalies"""
    
    def __init__(self, history_size=30, threshold_multiplier=2.0):
        """Initialize the metrics analyzer
        
        Args:
            history_size (int): Number of data points to keep for baseline calculation
            threshold_multiplier (float): Multiplier for standard deviation to determine threshold
        """
        self.history_size = history_size
        self.threshold_multiplier = threshold_multiplier
        
        # Metrics history for baseline calculation
        self.cpu_history = deque(maxlen=history_size)
        self.ram_history = deque(maxlen=history_size)
        self.disk_history = deque(maxlen=history_size)
        self.network_recv_history = deque(maxlen=history_size)
        self.network_sent_history = deque(maxlen=history_size)
        
        # Last analysis time
        self.last_analysis_time = 0
        
        logger.info("Metrics analyzer initialized")
    
    def analyze(self, metrics):
        """Analyze system metrics for anomalies
        
        Args:
            metrics (dict): System metrics to analyze
            
        Returns:
            dict: Analysis results with detected anomalies
        """
        # Update metrics history
        self._update_history(metrics)
        
        # Skip analysis if we don't have enough history
        if len(self.cpu_history) < 5:
            logger.info("Not enough history for baseline calculation")
            return {"anomalies": [], "has_anomalies": False}
        
        # Calculate baselines and thresholds
        cpu_baseline, cpu_threshold = self._calculate_baseline_threshold(self.cpu_history)
        ram_baseline, ram_threshold = self._calculate_baseline_threshold(self.ram_history)
        disk_baseline, disk_threshold = self._calculate_baseline_threshold(self.disk_history)
        net_recv_baseline, net_recv_threshold = self._calculate_baseline_threshold(self.network_recv_history)
        net_sent_baseline, net_sent_threshold = self._calculate_baseline_threshold(self.network_sent_history)
        
        # Detect anomalies
        anomalies = []
        
        # CPU usage anomaly
        if metrics['cpu_usage_percent'] > cpu_threshold:
            anomalies.append({
                'type': 'cpu_usage',
                'current': metrics['cpu_usage_percent'],
                'baseline': cpu_baseline,
                'threshold': cpu_threshold,
                'description': 'CPU usage is abnormally high'
            })
        
        # RAM usage anomaly (as percentage of total)
        ram_usage_percent = (metrics['ram_used'] / metrics['ram_total']) * 100
        if ram_usage_percent > ram_threshold:
            anomalies.append({
                'type': 'ram_usage',
                'current': ram_usage_percent,
                'baseline': ram_baseline,
                'threshold': ram_threshold,
                'description': 'RAM usage is abnormally high'
            })
        
        # Disk usage anomaly (as percentage of total)
        disk_usage_percent = (metrics['rom_used'] / metrics['rom_total']) * 100
        if disk_usage_percent > disk_threshold:
            anomalies.append({
                'type': 'disk_usage',
                'current': disk_usage_percent,
                'baseline': disk_baseline,
                'threshold': disk_threshold,
                'description': 'Disk usage is abnormally high'
            })
        
        # Network traffic anomalies
        # Only check if we have previous metrics for delta calculation
        if len(self.network_recv_history) > 1:
            # Calculate received bytes delta
            current_recv = metrics['bytes_received']
            prev_recv = self.network_recv_history[-2]
            recv_delta = current_recv - prev_recv if current_recv > prev_recv else 0
            
            if recv_delta > net_recv_threshold:
                anomalies.append({
                    'type': 'network_receive',
                    'current': recv_delta,
                    'baseline': net_recv_baseline,
                    'threshold': net_recv_threshold,
                    'description': 'Network receive traffic is abnormally high'
                })
            
            # Calculate sent bytes delta
            current_sent = metrics['bytes_sent']
            prev_sent = self.network_sent_history[-2]
            sent_delta = current_sent - prev_sent if current_sent > prev_sent else 0
            
            if sent_delta > net_sent_threshold:
                anomalies.append({
                    'type': 'network_send',
                    'current': sent_delta,
                    'baseline': net_sent_baseline,
                    'threshold': net_sent_threshold,
                    'description': 'Network send traffic is abnormally high'
                })
        
        # Update last analysis time
        self.last_analysis_time = time.time()
        
        return {
            "anomalies": anomalies,
            "has_anomalies": len(anomalies) > 0,
            "num_anomalies": len(anomalies),
            "analysis_time": self.last_analysis_time
        }
    
    def _update_history(self, metrics):
        """Update metrics history
        
        Args:
            metrics (dict): System metrics to add to history
        """
        self.cpu_history.append(metrics['cpu_usage_percent'])
        self.ram_history.append((metrics['ram_used'] / metrics['ram_total']) * 100)
        self.disk_history.append((metrics['rom_used'] / metrics['rom_total']) * 100)
        self.network_recv_history.append(metrics['bytes_received'])
        self.network_sent_history.append(metrics['bytes_sent'])
    
    def _calculate_baseline_threshold(self, history):
        """Calculate baseline and threshold for anomaly detection
        
        Args:
            history (deque): History of values
            
        Returns:
            tuple: (baseline, threshold)
        """
        # Convert deque to list for calculations
        values = list(history)
        
        # Calculate mean (baseline)
        baseline = sum(values) / len(values)
        
        # Calculate standard deviation
        variance = sum((x - baseline) ** 2 for x in values) / len(values)
        std_dev = variance ** 0.5
        
        # Calculate threshold as baseline + (std_dev * multiplier)
        threshold = baseline + (std_dev * self.threshold_multiplier)
        
        return baseline, threshold