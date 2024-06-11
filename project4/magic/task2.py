#!/usr/bin/env python3
from pwn import *
import os

# os.system('sudo ntpdate tock.stdtime.gov.tw')

if not os.path.exists('./modified_magic'):
    os.system('gcc -o modified_magic modified_magic.c')

r = remote("140.113.24.241", 30171)
exe = process("./modified_magic", stdout=PIPE)

r.recvuntil(b"Please enter the secret: ")
r.sendline(exe.stdout.read())

# Receive the response and split it into lines
response = r.recvall().decode("utf-8", "ignore").strip()
lines = response.splitlines()

# Print only the lines that contain 'FLAG'
for line in lines:
    if 'FLAG' in line:
        print(line)

r.close()