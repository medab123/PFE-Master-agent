import asyncio
import psutil
import time

class ResourceMonitoring:
    def __init__(self):
        """Initialize the ResourceMonitoring class."""
        pass

    def get_ram_usage(self):
        """Retrieve RAM usage metrics."""
        virtual_memory = psutil.virtual_memory()
        ram_total = virtual_memory.total
        ram_used = virtual_memory.used
        return {
            'ram_total': ram_total,
            'ram_used': ram_used,
            'ram_available': ram_total - ram_used,  # Derived value
        }

    def get_cpu_usage(self):
        """Retrieve CPU usage metrics."""
        return {
            'cpu_usage_percent': psutil.cpu_percent(interval=1)
        }

    def get_rom_usage(self):
        """Retrieve ROM (disk) usage metrics."""
        disk_usage = psutil.disk_usage('/')
        rom_total = disk_usage.total
        rom_used = disk_usage.used
        return {
            'rom_total': rom_total,
            'rom_used': rom_used,
            'rom_free': rom_total - rom_used,  # Derived value
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
        print(f"  Usage: {(ram_metrics['ram_used'] / ram_metrics['ram_total']) * 100:.2f}%")

        print("\nROM Usage:")
        print(f"  Total: {rom_metrics['rom_total'] / (1024**3):.2f} GB")
        print(f"  Used: {rom_metrics['rom_used'] / (1024**3):.2f} GB")
        print(f"  Free: {rom_metrics['rom_free'] / (1024**3):.2f} GB")
        print(f"  Usage: {(rom_metrics['rom_used'] / rom_metrics['rom_total']) * 100:.2f}%")

        print("\nNetwork Traffic:")
        print(f"  Bytes Sent: {network_metrics['bytes_sent'] / (1024**2):.2f} MB")
        print(f"  Bytes Received: {network_metrics['bytes_received'] / (1024**2):.2f} MB")
        print(f"  Packets Sent: {network_metrics['packets_sent']}")
        print(f"  Packets Received: {network_metrics['packets_received']}")

    async def start(self, client, sleep_time, batch_size=10):
        """Start monitoring system resources and send data to the server periodically in batches."""
        while True:
            batch_data = []
            for _ in range(batch_size):
                cpu_metrics = self.get_cpu_usage()
                ram_metrics = self.get_ram_usage()
                rom_metrics = self.get_rom_usage()
                network_metrics = self.get_network_traffic()
                data = {
                    'cpu_usage_percent': cpu_metrics['cpu_usage_percent'],
                    'ram_total': ram_metrics['ram_total'],
                    'ram_used': ram_metrics['ram_used'],
                    'ram_available': ram_metrics['ram_available'],
                    'rom_total': rom_metrics['rom_total'],
                    'rom_used': rom_metrics['rom_used'],
                    'rom_free': rom_metrics['rom_free'],
                    'bytes_sent': network_metrics['bytes_sent'],
                    'bytes_received': network_metrics['bytes_received'],
                    'packets_sent': network_metrics['packets_sent'],
                    'packets_received': network_metrics['packets_received'],
                }
                batch_data.append(data)
            await client.send('resource-monitoring', batch_data)

            print(f"{batch_size} metrics sent to server.")
            await asyncio.sleep(sleep_time)