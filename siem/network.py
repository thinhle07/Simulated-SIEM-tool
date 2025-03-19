import socket
from .core import SimpleSIEM

def monitor_network(siem: SimpleSIEM, port=514):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('localhost', port))
        sock.listen(1)
        print(f"Network monitoring started on port {port}")
        
        while siem.running:
            conn, addr = sock.accept()
            data = conn.recv(1024)
            if data:
                siem.collect_log(f"Network event from {addr}: {data.decode()}")
            conn.close()
    except Exception as e:
        print(f"Network monitoring error: {e}")
