from pwn import *
offset = cyclic_find(0x7ffff7e219fc)

print(offset)