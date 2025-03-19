import time
import threading
from siem.core import SimpleSIEM
from siem.app import SimpleApp
from siem.network import monitor_network

def main():
    siem = SimpleSIEM()
    app = SimpleApp(siem)
    
    net_thread = threading.Thread(target=monitor_network, args=(siem, 514))
    net_thread.daemon = True
    net_thread.start()

    print("Simple App with SIEM Monitoring")
    print("Commands: login <user> <pass>, logout, view, download, update, exit")
    
    try:
        while True:
            cmd = input("> ").strip().split()
            if not cmd:
                continue
            
            action = cmd[0].lower()
            if action == "login" and len(cmd) >= 3:
                app.login(cmd[1], cmd[2])
            elif action == "logout":
                app.logout()
            elif action == "view":
                app.perform_action("view")
            elif action == "download":
                app.perform_action("download")
            elif action == "update":
                app.perform_action("update")
            elif action == "exit":
                break
            else:
                print("Unknown command")
            time.sleep(0.1)
    
    except KeyboardInterrupt:
        print("\nShutting down...")
    
    siem.running = False
    time.sleep(1)
    print(f"Total logs processed: {len(siem.logs)}")
    print(f"Total alerts generated: {len(siem.alerts)}")

if __name__ == "__main__":
    main()