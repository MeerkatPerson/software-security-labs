
import angr
import claripy


# function for reversing bits from https://www.geeksforgeeks.org/reverse-actual-bits-given-number/

# function to reverse
# bits of a number
def reverseBits(n):

    rev = 0

    # traversing bits of 'n' from the right
    while (n > 0):

        # bitwise left shift 'rev' by 1
        rev = rev << 1

        # if current bit is '1'
        if (n & 1 == 1):
            rev = rev ^ 1

        # bitwise right shift 'n' by 1
        n = n >> 1

    # required number
    return rev

# adapted from https://ctftime.org/writeup/22420
# Adaptation: use other polynomial


def get_crc32_calc_BVV(ind):

    # crc = ind.zero_extend(64 - ind.size())  # arg2 starts with BVV(0, 32) ?
    #                                       (Get unequal lengths error) if I leave this
    #                                       at 'ind.zero_extend(64 - ind.size())' after
    #                                       ensuring that arg2/dst starts with BVV(0, 32)
    crc = ind.zero_extend(32 - ind.size())
    if isinstance(crc, angr.state_plugins.sim_action_object.SimActionObject):
        crc = crc.to_claripy()

    # poly_reversed = reverseBits(0x04c11db7)
    poly_reversed = 0xEDB88320

    for j in range(8):

        shift = ((crc >> 1) & 0x7FFFFFFF)
        cond = crc & 1 > 0
        crc = claripy.If(cond, shift ^ poly_reversed, shift)
        # crc = claripy.If(cond, shift ^ 0x04c11db7, shift)

    return crc


# adapted from https://ctftime.org/writeup/22420
# Adaptation: basically only the length of src (16 bytes instead of 4)
def crc32(src, dst):

    b128 = src

    # NOTE need to negate dst due to peculiarities of crc32
    crc32val = ~dst

    # NOTE in the ctf write-up, they were iterating in reverse order because
    #       their bit vectors were little endian.
    #       Here, we're dealing with big endians, thus iterating 'normally'
    for i in range(16):

        b = b128.get_byte(i)

        # NOTE should I now shift by 16 rather than 8 bytes because of arg2
        #       starting with 'BVV(0, 32)'?
        shift = (
            (crc32val >> 8) & 0x00FFFFFF)

        # NOTE in the ctf write-up, 'crc32val.get_byte(3)' was used -
        #      but there, they were dealing with little endians,
        #      and here we are dealing with big endian, so 'crc32val.get_byte(0)'
        #      should be correct

        lookupInd = (crc32val.get_byte(3) ^ b)

        crc32val = get_crc32_calc_BVV(lookupInd) ^ shift

    # NOTE need to negate crc32val due to peculiarities of crc32
    return ~crc32val


flag_len = 16

# BVS = a bit vector with a symbolic value
arg1 = claripy.BVS('arg1', flag_len*8)

s = claripy.Solver()

# Enforce all characters to belong to the charset
for x in arg1.chop(8):

    s.add(x >= 0x41)
    s.add(x <= 0x5a)

# Enforce the first four characters to be 'FLAG'
s.add(arg1.get_byte(0) == ord('F'))
s.add(arg1.get_byte(1) == ord('L'))
s.add(arg1.get_byte(2) == ord('A'))
s.add(arg1.get_byte(3) == ord('G'))

# make arg2 a BVV
arg2 = claripy.BVV(0, 32)

'''
USE HINT:
'You could even pass `x` and `y` through functions that apply mathematical transformations(like the
ones used above) to generate new ASTs and use those to add constraints to the solver and find
solutions to the obtained system. This will come extra handy in the CRC32 challenge below.'
'''
crcval = crc32(arg1, arg2)

# the crc32 of arg1 prefixed with FLAG should correspond to the given value
s.add(crcval == 0x3e5074ba)

arg1_v = s.eval(arg1, 1)[0]
print(arg1_v.to_bytes(flag_len, byteorder='big'))
