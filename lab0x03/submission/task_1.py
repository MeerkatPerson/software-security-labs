from tkinter import Y
import claripy
import json

x = claripy.BVS('a', 32)  # create a 32-bit symbolic variable named 'a'
y = claripy.BVS('b', 32)

s = claripy.Solver()
s.add((x - 0x13d & 0xf9) - y == 0xfffff496)
s.add(x - (0x328 & y - (y & 0x284)) == 0xa55)
s.add(x ^ y + y % 0x180 ^ 0x95 == 0x75c)
s.add(0xf5 % ((y | (x & x + (x ^ y)) * x) + 0x5) == 0xf5)
s.add(((0x4a | x | y) & x) - 0x220 == 0x93d)

xv = s.eval(x, 1)[0]
print(xv)

yv = s.eval(y, 1)[0]
print(yv)

results = {"x": xv, "y": yv}

with open("task_1.json", "w") as outfile:
    json.dump(results, outfile)
