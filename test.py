import socket
import pickle
import threading
import signal
import sys
from queue import Queue
import struct

# Global flag to control server shutdown
shutdown_flag = threading.Event()


def receive_data(client_socket):
    try:
        # Read the length header (4 bytes)
        raw_length = client_socket.recv(4)
        if not raw_length:
            raise ValueError("Connection closed or no data received.")
        data_length = struct.unpack('!I', raw_length)[0]
        print(f"Expected data length: {data_length}")

        # Read the exact data_length bytes
        received_data = b""
        while len(received_data) < data_length:
            print('start data reciving ....')

            chunk = client_socket.recv(min(1024, data_length - len(received_data)))
            print('recived chank',len(received_data))

            if not chunk:
                raise ValueError("Connection closed before receiving all data.")
            received_data += chunk

        # Deserialize the data
        deserialized_data = pickle.loads(received_data)
        return deserialized_data
    except Exception as e:
        print(f"Error in receive_data: {e}")
        return None
    except Exception as e:
        print(f"Error in receive_data: {e}")
        return None

def handle_client(client_socket, client_address, log_queue):
    """Handle an individual client connection."""
    log_queue.put(f"Connection established with {client_address}")
    try:
        while not shutdown_flag.is_set():
            # Receive the serialized packet data
            data = client_socket.recv(4096)  # Adjust buffer size as needed
            if not data:
                break

            # Deserialize the data
            try:
                received_data = receive_data(client_socket)
                data_type = received_data.get("type")
                data_content = received_data.get("data")

                if data_type == "resource":  # Resource metrics
                    log_queue.put("Received Resource Metrics:")
                    log_queue.put(f"CPU: {data_content.get('cpu', {})}")
                    log_queue.put(f"RAM: {data_content.get('ram', {})}")
                    log_queue.put(f"ROM: {data_content.get('rom', {})}")
                    log_queue.put(f"Network: {data_content.get('network', {})}")
                elif data_type == "traffic":  # Traffic packets
                    log_queue.put("Received Traffic Packets:")
                    for packet in data_content:
                        log_queue.put(packet)
                elif data_type == "user_activity":  # User activity metrics
                    log_queue.put("Received User Activity Data:")
                    log_queue.put(f"Logged-in Users: {data_content.get('logged_in_users', [])}")
                    log_queue.put(f"Running Processes: {data_content.get('running_processes', [])}")
                else:
                    log_queue.put("Unknown data type received.")
            except Exception as e:
                log_queue.put(f"Error deserializing data: {e}")
    except ConnectionResetError:
        log_queue.put(f"Connection reset by {client_address}")
    except Exception as e:
        log_queue.put(f"Unexpected error with {client_address}: {e}")
    finally:
        log_queue.put(f"Closing connection with {client_address}")
        client_socket.close()

def log_listener(log_queue):
    """Log messages from the queue in a thread-safe manner."""
    while not shutdown_flag.is_set():
        try:
            message = log_queue.get(timeout=1)  # Wait for a log message
            print(message)
        except:
            continue  # Timeout reached, loop again for shutdown check

def start_server(host="0.0.0.0", port=3000, buffer_size=4096):
    """Start the server to listen for incoming connections."""
    global shutdown_flag

    # Create a thread-safe queue for logging
    log_queue = Queue()

    # Start the log listener thread
    log_thread = threading.Thread(target=log_listener, args=(log_queue,))
    log_thread.daemon = True
    log_thread.start()

    # Create the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    log_queue.put(f"Server listening on {host}:{port}...")

    # Handle graceful shutdown
    def signal_handler(sig, frame):
        log_queue.put("Shutting down server...")
        shutdown_flag.set()
        server_socket.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Accept client connections
    try:
        while not shutdown_flag.is_set():
            try:
                client_socket, client_address = server_socket.accept()
                log_queue.put(f"New connection from {client_address}")

                # Handle the client in a separate thread
                client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address, log_queue))
                client_thread.daemon = True  # Allow the thread to exit when the main program ends
                client_thread.start()
            except socket.error:
                if not shutdown_flag.is_set():
                    log_queue.put("Socket error occurred.")
    finally:
        log_queue.put("Server has been shut down.")
        sys.exit(0)

if __name__ == "__main__":
    start_server()
