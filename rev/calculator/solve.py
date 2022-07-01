from z3 import *

a = [BitVec(f'a[{i}]', 8) for i in range(46)]
solver = Solver()

solver.add(a[0] == ord('A'))

# AIS3
offset = 1
solver.add(a[14+offset] == ord('A'))
solver.add(a[3+offset] == ord('{'))
array = [30, 4, 100]
for i in range(len(array)):
    solver.add((a[i+offset] ^ ord('W')) == array[i])
print(solver.check())


# AIS33
offset += 3 + 1
solver.add(a[40+offset] == ord('}'))
solver.add(a[0+offset] == ord('D'))
array = [5, 29, 5]
for i in range(len(array)):
    solver.add((a[37+i+offset] ^ ord('B')) == array[i])
print(solver.check())

# AIS333
offset += 0 + 1
solver.add(a[35+offset] == a[34+offset])
solver.add(a[34+offset] == ord('_'))
solver.add(a[15+offset] == ord('k'))
array = [10, 110, 101, 116, 9, 110, 101, 124, 104, 123, 87, 9, 109, 10, 72]
for i in range(15):
    solver.add((a[i+offset] ^ ord(':')) == array[i])
print(solver.check())

# AIS3333
offset += 15 + 1
solver.add(a[6+offset] == ord('_'))
solver.add(a[5+offset] == a[8+offset])
solver.add(a[3+offset] == a[6+offset])
solver.add(a[1+offset] == ord('1'))
solver.add(a[2+offset] == ord('5'))
solver.add(a[7+offset] == ord('C'))
solver.add(a[8+offset] == ord('0'))
solver.add(a[6+offset] == a[0+offset])
solver.add(a[4+offset] == ord('S'))
array = [9, 52, 8, 13, 7, 5, 48, 87, 0]
for i in range(len(array)):
    solver.add((a[9+i+offset] ^ ord('d')) == array[i])
print(solver.check())

out = ''
m = solver.model()
for i in range(len(a)):
    try:
        out += chr(m[a[i]].as_long())
    except:
        out += '?'
print(out)

# Flag: AIS3{D0T_N3T_FRAm3W0rk_15_S0_C0mPlicaT3d__G_G}
