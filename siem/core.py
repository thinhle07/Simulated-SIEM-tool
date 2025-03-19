import time
import json
from datetime import datetime
import os
import re

class SimpleSIEM:
    def __init__(self, log_file='siem_logs.txt'):
        self.logs = []
        self.alerts = []
        self.log_file = log_file
        self.running = True
        self.current_user = None
        
        self.rules = {
            'multiple_failed_logins': {'pattern': r'login failed', 'threshold': 3, 'time_window': 60},
            'suspicious_ip': {'pattern': r'192\.168\.\d+\.\d+', 'threshold': 5, 'time_window': 600},
            'rapid_actions': {'pattern': r'(viewed data|downloaded data)', 'threshold': 10, 'time_window': 300},
            'unauthorized_access': {'pattern': r'unauthorized attempt', 'threshold': 1, 'time_window': 3600}
        }

    def collect_log(self, log_entry, user=None):
        timestamp = datetime.now().isoformat()
        log = {
            'timestamp': timestamp,
            'message': log_entry,
            'user': user or self.current_user or 'unknown',
            'processed': False
        }
        self.logs.append(log)
        self.append_log_to_file(log)
        self.analyze_log(log)

    def analyze_log(self, log):
        for rule_name, rule in self.rules.items():
            if re.search(rule['pattern'], log['message'], re.IGNORECASE):
                self.check_rule_violation(rule_name, rule, log)

    def check_rule_violation(self, rule_name, rule, current_log):
        current_time = datetime.fromisoformat(current_log['timestamp'])
        time_window_start = current_time.timestamp() - rule['time_window']
        
        matches = [
            log for log in self.logs 
            if (datetime.fromisoformat(log['timestamp']).timestamp() >= time_window_start and
                re.search(rule['pattern'], log['message'], re.IGNORECASE) and
                log['user'] == current_log['user'])
        ]
        
        if len(matches) >= rule['threshold']:
            self.generate_alert(rule_name, matches)

    def generate_alert(self, rule_name, matched_logs):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'rule': rule_name,
            'severity': 'HIGH' if len(matched_logs) > self.rules[rule_name]['threshold'] * 1.5 else 'MEDIUM',
            'user': matched_logs[0]['user'],
            'count': len(matched_logs),
            'details': [log['message'] for log in matched_logs[-5:]]
        }
        
        if not any(a['rule'] == rule_name and a['user'] == alert['user'] and 
                  (datetime.now() - datetime.fromisoformat(a['timestamp'])).seconds < 300 
                  for a in self.alerts):
            self.alerts.append(alert)
            self.display_alert(alert)

    def display_alert(self, alert):
        print(f"\n[!] SUSPICIOUS ACTIVITY DETECTED - {alert['timestamp']}")
        print(f"User: {alert['user']}")
        print(f"Rule: {alert['rule']}")
        print(f"Severity: {alert['severity']}")
        print(f"Occurrences: {alert['count']}")
        print("Recent suspicious events:")
        for detail in alert['details']:
            print(f"  - {detail}")
        print("-" * 50)

    def append_log_to_file(self, log):
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log) + '\n')
        except Exception as e:
            print(f"Error writing log to file: {e}")

    def load_logs(self):
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    self.logs = [json.loads(line.strip()) for line in f if line.strip()]
            except Exception as e:
                print(f"Error loading logs: {e}")
