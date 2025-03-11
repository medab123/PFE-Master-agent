from resource.resource_monitoring import ResourceMonitoring
from resource.trafic_monitoring import TrafficMonitoring
from resource.user_activity_monitoring import UserActivityMonitoring
import socket
import time
from multiprocessing import Process
import sqlite3

server_ip = "0.0.0.0"
server_port = 3000
sleep_time = 3
def connect():
    """Create a connection to the server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((server_ip, server_port))
    return server_socket

def sync_resource(connection):
    """Sync resource metrics with the server."""
    resource_monitor = ResourceMonitoring()
    while True:
        resource_monitor.sync_with_server(connection)
        time.sleep(sleep_time)  # Adjust interval as needed

def sync_traffic(connection):
    """Sync traffic metrics with the server."""
    traffic_monitor = TrafficMonitoring()
    while True:
        traffic_monitor.sync_traffic_with_server(connection, packet_range=20)
        time.sleep(sleep_time)  # Adjust interval as needed

def sync_user_activity(connection):
    """Sync user activity metrics with the server."""
    user_activity_monitor = UserActivityMonitoring()
    while True:
        user_activity_monitor.sync_with_server(connection)
        time.sleep(sleep_time)  # Adjust interval as needed

if __name__ == "__main__":
    db_connection = sqlite3.connect('database.db')
    
    # Display initial metrics
    resource_monitoring = ResourceMonitoring()
    resource_monitoring.save_metrics_to_database(db_connection)
    user_activity_monitoring = UserActivityMonitoring()
    user_activity_monitoring.write_to_database(db_connection)


    traffic_monitor = TrafficMonitoring()
    # Capture and save network traffic to the database
    traffic_monitor.save_traffic_to_database(db_connection)
    db_connection.close()
    # resource_monitoring.display_metrics()
    # user_activity_monitoring.display_user_activity()

    # Establish connections for each process
    # resource_connection = connect()
    # traffic_connection = connect()
    # user_activity_connection = connect()

    # Create and start processes
    # resource_process = Process(target=sync_resource, args=(resource_connection,))
    # traffic_process = Process(target=sync_traffic, args=(traffic_connection,))
    # user_activity_process = Process(target=sync_user_activity, args=(user_activity_connection,))

    # resource_process.start()
    # traffic_process.start()
    # user_activity_process.start()

    # Wait for processes to complete (optional, unless you need blocking)
    # resource_process.join()
    # traffic_process.join()
    # user_activity_process.join()
