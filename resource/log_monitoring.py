import os

class LogMonitoring:
    def __init__(self, log_base_directory="/var/log"):
        """Initialize the class with the base log directory."""
        self.log_base_directory = log_base_directory
        self.log_files = self.get_all_log_files()

    def get_all_log_files(self):
        """Retrieve all log files from the base log directory and its subdirectories."""
        log_files = []
        try:
            # Walk through all directories starting from the base log directory
            for root, dirs, files in os.walk(self.log_base_directory):
                for file in files:
                    # Only add files that are typically log files (can add extensions like .log, .gz, etc.)
                    if file.endswith(".log") or file.endswith(".gz") or file.startswith("syslog") or file.startswith("messages"):
                        log_files.append(os.path.join(root, file))
        except PermissionError as e:
            print(f"Permission denied: {e}")
        except Exception as e:
            print(f"Error retrieving log files: {e}")
        return log_files

    def read_log_file(self, file_path):
        """Read the content of a log file."""
        if file_path in self.log_files:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                return content
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
        else:
            print(f"File {file_path} not found in the log directories.")
            return None

    def analyze_logs(self):
        """Analyze all retrieved log files."""
        for log_file in self.log_files:
            print(f"Reading {log_file}...")
            content = self.read_log_file(log_file)
            if content:
                # Just print the first 200 characters of each log for now
                print(content[:200])
                print("-" * 40)