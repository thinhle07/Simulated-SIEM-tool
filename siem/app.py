import random
from .core import SimpleSIEM

class SimpleApp:
    def __init__(self, siem: SimpleSIEM):
        self.siem = siem

    def login(self, username, password):
        if random.random() < 0.8:
            self.siem.current_user = username
            self.siem.collect_log(f"Login successful for user {username}")
            print(f"Welcome, {username}!")
        else:
            self.siem.collect_log(f"Login failed for user {username}")
            print("Login failed")

    def logout(self):
        if self.siem.current_user:
            self.siem.collect_log(f"Logout for user {self.siem.current_user}")
            print(f"Goodbye, {self.siem.current_user}!")
            self.siem.current_user = None

    def perform_action(self, action):
        if not self.siem.current_user:
            print("Please log in first!")
            return
        
        if action == "view":
            self.siem.collect_log("Viewed data")
        elif action == "download":
            if random.random() < 0.9:
                self.siem.collect_log("Downloaded data")
            else:
                self.siem.collect_log("Unauthorized attempt to download data")
        elif action == "update":
            self.siem.collect_log("Updated profile")
        print(f"Action '{action}' performed")
