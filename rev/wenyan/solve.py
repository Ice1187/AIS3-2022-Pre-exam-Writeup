import subprocess as sp
import string
from itertools import product


def run_cmd(cmd):
    cmd = '蛵煿 ' + cmd
    p = sp.run(['./node_modules/.bin/wenyan --dir ./chal/藏書樓/ ./chal/殼.wy'],
               shell=True, capture_output=True, input=cmd.encode())
    # f'echo -n "{cmd}" | ./node_modules/.bin/wenyan --dir ./chal/藏書樓/ ./chal/殼.wy').read().strip()
    res = p.stdout
    res = res[res.find(b' ')+1:]
    res = res[res.find(b' ')+1:]
    res = res[:res.find(b' ')]
    # print(res)
    return res


# create dict
#d = {}
#cnt = 0
# for cmd in list(product(string.printable, repeat=3))[500000:]:
#    cmd = ''.join(cmd)
#    res = run_cmd(cmd)[:14*2]
#    d[res] = cmd
#    cnt += 1
#    if cnt % 500 == 0:
#        with open(f'./checkpoint/500000_{cnt}', 'w') as f:
#            f.write(str(d))
#        print(cmd, res.decode())

# read checkpoint
d = {}
with open('checkpoint/500000', 'r') as f:
    data = f.read()
d = eval(data)
with open('checkpoint/500000_381000', 'r') as f:
    data = f.read()
d2 = eval(data)
d.update(d2)

print('dict len:', len(d))

with open('ans.txt', 'rb') as f:
    data = f.read()

flag = ''
for i in range(0, len(data)//14, 2):
    flag += d[data[i*14:(i+2)*14]]

print(flag)

# Flag: AIS3{chaNcH4n_a1_Ch1k1ch1k1_84n8An_M1nNa_5upa5utA_n0_TAMa90_5a}
