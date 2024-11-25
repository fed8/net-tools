import socket
from concurrent.futures import ThreadPoolExecutor
import sys
import socket
import os

def get_pc_name():
    return socket.gethostname()

def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = sock.connect_ex((host, port))
    if result == 0:
        print(f"\033[92m[+] {port}\033[0m")
    sock.close()

def scan_all_ports(host):
    ports = range(1, 65536)
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda port: scan_port(host, port), ports)

if __name__ == "__main__":

    os.system('mode 38, 20')
    pc_name = get_pc_name
    os.system('cls')
    target_host = input(f"[root@{get_pc_name()}]━━>>> ")
    os.system('cls')
    scan_all_ports(target_host)
    os.system('pause >nul')