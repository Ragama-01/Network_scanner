import socket
import time
from concurrent.futures import ThreadPoolExecutor

def scan_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((host, port))
    if result == 0:
        print(f"Port {port} is OPEN")

start = time.time()

with ThreadPoolExecutor(max_workers=100) as executor:#how many tasks to run concurrently
    for port in range(1, 101):
        executor.submit(scan_port, "google.com", port)

end = time.time()
print(f"\nTook {end - start:.2f} seconds")