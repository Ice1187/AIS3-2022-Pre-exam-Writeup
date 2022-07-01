M = 2**1024

with open('./output.txt', 'r') as f:
    enc_flag = f.read().strip()
enc_flag = int(enc_flag, 16).to_bytes(64, 'big').strip(b'\x00')


def f(x):
    # this is a *fast* function
    return (
        4 * x**4 + 8 * x**8 + 7 * x**7 + 6 * x**6 + 3 * x**3 + 0x48763
    ) % M


def decrypt(key):
    flag = ''
    for e in enc_flag:
        flag += chr(e ^ (key & 0xff))
        key = f(key)
    if 'AIS3' in flag:
        print(flag)
        exit(0)


for k in range(2**1024):
    tmp = ''
    tmp_k = k
    for c in enc_flag[:4]:
        tmp += chr(c ^ (tmp_k & 0xff))
        tmp_k = f(tmp_k)
    if tmp == 'AIS3':
        print('repeat!', k)
        decrypt(k)
        break

# Flag: AIS3{not_every_bits_are_used_lol}
