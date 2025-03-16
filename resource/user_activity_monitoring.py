import asyncio
import psutil
import sqlite3
from datetime import datetime


class UserActivityMonitoring:
    def __init__(self):
        """Initialize the UserActivityMonitoring class."""
        pass

    def get_logged_in_users(self):
        """Retrieve details of logged-in users."""
        return [{'name': user.name, 'host': user.host, 'started': user.started} for user in psutil.users()]

    def get_running_processes(self):
        """Retrieve details of running processes."""
        processes = []
        for process in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
            processes.append(process.info)
        return processes

    def display_user_activity(self):
        """Display user activity metrics."""
        logged_in_users = self.get_logged_in_users()
        running_processes = self.get_running_processes()

        print("\nUser Activity:")
        print("Logged-in Users:")
        for user in logged_in_users:
            print(f"  Name: {user['name']}, Host: {user['host']}, Started: {user['started']}")

        print("Top Running Processes:")
        for process in running_processes[:5]:  # Show top 5 processes
            print(f"  PID: {process['pid']}, Name: {process['name']}, CPU: {process['cpu_percent']}%, Memory: {process['memory_percent']}%")

   
    def write_to_database(self, db_connection):
        """Write user activity data into an SQLite database."""
        cursor = db_connection.cursor()

        # Create tables if they don't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logged_in_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                started INTEGER NOT NULL,
                sync INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name, host)  -- Ensure uniqueness for combination of name and host
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS running_processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER NOT NULL UNIQUE,
                name TEXT NOT NULL,
                username TEXT NOT NULL,
                cpu_percent REAL NOT NULL,
                memory_percent REAL NOT NULL,
                sync INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Insert or update logged-in users data
        logged_in_users = self.get_logged_in_users()
        cursor.executemany('''
            INSERT INTO logged_in_users (name, host, started, sync, created_at, updated_at)
            VALUES (:name, :host, :started, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(name, host) DO UPDATE SET
                started = excluded.started,
                updated_at = CURRENT_TIMESTAMP
        ''', logged_in_users)

        # Insert or update running processes data
        running_processes = self.get_running_processes()
        cursor.executemany('''
            INSERT INTO running_processes (pid, name, username, cpu_percent, memory_percent, sync, created_at, updated_at)
            VALUES (:pid, :name, :username, :cpu_percent, :memory_percent, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(pid) DO UPDATE SET
                name = excluded.name,
                username = excluded.username,
                cpu_percent = excluded.cpu_percent,
                memory_percent = excluded.memory_percent,
                updated_at = CURRENT_TIMESTAMP
        ''', running_processes)

        # Commit the transaction
        db_connection.commit()
        print("Data written to database successfully.")

    def prepare_user_activity_data(self):
        """Prepare the user activity data to send to the server."""
        logged_in_users = self.get_logged_in_users()
        running_processes = self.get_running_processes()

        data = {
            "logged_in_users": logged_in_users,
            "running_processes": running_processes,
        }
        return data

    async def start(self, client, sleep_time=5, batch_size=10):
        """Start monitoring user activity and sending data to the server periodically."""
        while True:
            print("Starting user activity monitoring...")
            
            # Prepare the user activity data
            user_activity_data = self.prepare_user_activity_data()

            # Send the data directly to the server (WebSocket)
            await client.send('user-activity', user_activity_data)
            
            print(f"User activity data sent to server at {datetime.now()}.")

            # Sleep for the specified interval before the next monitoring cycle
            await asyncio.sleep(sleep_time)