# Simulated-SIEM-tool
SimpleSIEM is a Python-based Security Information and Event Management (SIEM) system for real-time log collection, analysis, and alerting. Paired with a simple app simulation, it detects suspicious activities like failed logins and unauthorized access.

## Key Features
- Log Collection: Captures and stores logs with timestamps, user information, and event details in a file (siem_logs.txt).
- Rule-Based Analysis: Detects predefined patterns (e.g., failed logins, suspicious IPs) using regex and configurable thresholds.
- Real-Time Alerts: Generates and displays alerts with severity levels (MEDIUM/HIGH) based on rule violations.
- Network Monitoring: Listens for network events on a specified port (default: 514) via TCP socket.
- Simulated Application: Includes a basic app with user login/logout and actions (view, download, update) to generate logs for testing.
- Multi-Threaded: Runs network monitoring in a separate thread for uninterrupted operation.

## How it works
1. The SimpleSIEM class manages log collection, analysis, and alerting based on customizable rules.
2. The SimpleApp class simulates user interactions, feeding events into the SIEM.
3. Logs are analyzed against rules with time windows and thresholds, triggering alerts for suspicious patterns.
4. Alerts are displayed in real-time with details of recent events.

## Usage
*In terminal
```python main.py```
Commands: login <user> <pass>, logout, view, download, update, exit
Logs are appended to siem_logs.txt, and alerts are printed to the console.

## Used for
Learning about SIEM concepts and implementation.
Prototyping basic security monitoring systems.
Testing log analysis and alerting workflows.
