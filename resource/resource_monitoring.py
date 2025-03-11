import psutil
import pickle
import sqlite3

class ResourceMonitoring:
    def __init__(self):
        """Initialize the ResourceMonitoring class."""
        pass

    def get_ram_usage(self):
        """Retrieve RAM usage metrics."""
        virtual_memory = psutil.virtual_memory()
        return {
            'ram_total': virtual_memory.total,
            'ram_used': virtual_memory.used,
            'ram_available': virtual_memory.available,
            'ram_usage_percent': virtual_memory.percent
        }

    def get_cpu_usage(self):
        """Retrieve CPU usage metrics."""
        return {
            'cpu_usage_percent': psutil.cpu_percent(interval=1)
        }

    def get_rom_usage(self):
        """Retrieve ROM (disk) usage metrics."""
        disk_usage = psutil.disk_usage('/')
        return {
            'rom_total': disk_usage.total,
            'rom_used': disk_usage.used,
            'rom_free': disk_usage.free,
            'rom_usage_percent': disk_usage.percent
        }

    def get_network_traffic(self):
        """Retrieve network traffic metrics."""
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_received': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_received': net_io.packets_recv
        }

    def display_metrics(self):
        """Retrieve and display system metrics."""
        ram_metrics = self.get_ram_usage()
        cpu_metrics = self.get_cpu_usage()
        rom_metrics = self.get_rom_usage()
        network_metrics = self.get_network_traffic()

        print("System Metrics:")
        print(f"CPU Usage: {cpu_metrics['cpu_usage_percent']}%")

        print("\nRAM Usage:")
        print(f"  Total: {ram_metrics['ram_total'] / (1024**3):.2f} GB")
        print(f"  Used: {ram_metrics['ram_used'] / (1024**3):.2f} GB")
        print(f"  Available: {ram_metrics['ram_available'] / (1024**3):.2f} GB")
        print(f"  Usage: {ram_metrics['ram_usage_percent']}%")

        print("\nROM Usage:")
        print(f"  Total: {rom_metrics['rom_total'] / (1024**3):.2f} GB")
        print(f"  Used: {rom_metrics['rom_used'] / (1024**3):.2f} GB")
        print(f"  Free: {rom_metrics['rom_free'] / (1024**3):.2f} GB")
        print(f"  Usage: {rom_metrics['rom_usage_percent']}%")

        print("\nNetwork Traffic:")
        print(f"  Bytes Sent: {network_metrics['bytes_sent'] / (1024**2):.2f} MB")
        print(f"  Bytes Received: {network_metrics['bytes_received'] / (1024**2):.2f} MB")
        print(f"  Packets Sent: {network_metrics['packets_sent']}")
        print(f"  Packets Received: {network_metrics['packets_received']}")

    def sync_with_server(self, server_socket):
        """Synchronize metrics with the remote server."""
        # Gather all metrics
        metrics = {
            "cpu": self.get_cpu_usage(),
            "ram": self.get_ram_usage(),
            "rom": self.get_rom_usage(),
            "network": self.get_network_traffic()
        }

        print(metrics)
        # Serialize the data
        data_to_send = pickle.dumps({"type": "resource", "data": metrics})  # Add a type key

        # Send data to the server
        print("Sending metrics to the server...")
        server_socket.sendall(data_to_send)
        print("Metrics sent successfully.")

    def save_metrics_to_database(self, db_connection):
        """Save resource metrics to an SQLite database."""
        cursor = db_connection.cursor()

        # Create tables if they don't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS resource_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cpu_usage_percent REAL NOT NULL,
                ram_total INTEGER NOT NULL,
                ram_used INTEGER NOT NULL,
                ram_available INTEGER NOT NULL,
                ram_usage_percent REAL NOT NULL,
                rom_total INTEGER NOT NULL,
                rom_used INTEGER NOT NULL,
                rom_free INTEGER NOT NULL,
                rom_usage_percent REAL NOT NULL,
                bytes_sent INTEGER NOT NULL,
                bytes_received INTEGER NOT NULL,
                packets_sent INTEGER NOT NULL,
                packets_received INTEGER NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sync INTEGER DEFAULT 0
            )
        ''')

        # Capture metrics
        cpu_metrics = self.get_cpu_usage()
        ram_metrics = self.get_ram_usage()
        rom_metrics = self.get_rom_usage()
        network_metrics = self.get_network_traffic()

        # Insert metrics data into the database
        cursor.execute('''
            INSERT INTO resource_metrics (
                cpu_usage_percent, ram_total, ram_used, ram_available, ram_usage_percent,
                rom_total, rom_used, rom_free, rom_usage_percent, bytes_sent, bytes_received,
                packets_sent, packets_received, sync
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        ''', (
            cpu_metrics['cpu_usage_percent'], ram_metrics['ram_total'], ram_metrics['ram_used'],
            ram_metrics['ram_available'], ram_metrics['ram_usage_percent'],
            rom_metrics['rom_total'], rom_metrics['rom_used'], rom_metrics['rom_free'],
            rom_metrics['rom_usage_percent'], network_metrics['bytes_sent'],
            network_metrics['bytes_received'], network_metrics['packets_sent'],
            network_metrics['packets_received']
        ))

        # Commit the transaction
        db_connection.commit()
        print("Metrics saved to database successfully.")
