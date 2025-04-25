# Sec-Spot Server Monitoring Agent

## Overview

The Sec-Spot agent is a Python-based monitoring system that collects metrics and security information from servers. It's designed to work with the Sec-Spot backend to provide comprehensive server monitoring and security analysis.

## Key Features

- **System Metrics Monitoring**: CPU, RAM, disk usage, and network traffic
- **Network Traffic Analysis**: Monitoring of network connections and packet data
- **Security Monitoring**: Detection of suspicious activities and potential threats
- **Log Analysis**: Collection and analysis of system and application logs
- **Anomaly Detection**: Identification of abnormal system behavior
- **Real-time Alerts**: Notifications for security events and system anomalies

## Architecture

The agent is built with a modular, maintainable architecture:

- **Collectors**: Gather data from different sources (system metrics, network traffic, security events, logs)
- **Analyzers**: Process collected data to detect anomalies and security threats
- **WebSocket Client**: Communicates with the backend server in real-time
- **Core Agent**: Orchestrates all components and manages the monitoring lifecycle

## Installation

### Prerequisites

- Python 3.6+
- Linux-based operating system (Ubuntu recommended)
- Root or sudo access for system monitoring

### Automatic Installation

The agent can be installed automatically via the Sec-Spot dashboard by adding a server and following the installation instructions.

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/medab123/PFE-Master-agent.git
   ```

2. Install dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

3. Create configuration file:
   ```bash
   cp config.env.example config.env
   ```

4. Edit the configuration file with your server details:
   ```bash
   nano config.env
   ```

5. Install the systemd service:
   ```bash
   cp sec-spot-agent.service /etc/systemd/system/
   systemctl enable sec-spot-agent.service
   systemctl start sec-spot-agent.service
   ```

## Configuration

The agent is configured via the `config.env` file. Key configuration options include:

- `SERVER_ID`: Unique identifier assigned by the Sec-Spot backend
- `REVERB_URI`: WebSocket server URL for communication
- `MONITORING_INTERVAL`: Frequency of system metrics collection (in seconds)
- `LOG_LEVEL`: Logging detail level (DEBUG, INFO, WARNING, ERROR)

## Security Considerations

- The agent requires root privileges to access system information
- All communication with the backend is authenticated
- No sensitive data is stored locally by the agent
- Network traffic analysis is limited to metadata, not packet contents

## Troubleshooting

Common issues and their solutions:

1. **Agent not starting**: Check the service status with `systemctl status sec-spot-agent.service`
2. **Connection failures**: Verify network connectivity and WebSocket URI in config
3. **High CPU usage**: Adjust the monitoring intervals in the configuration
4. **Missing data**: Check log files for collection errors

## License

This project is part of the PFE Master project by [Your Name].

## Contributors

- [Your Name]