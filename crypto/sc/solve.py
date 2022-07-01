import string

charset = list(string.ascii_lowercase + string.ascii_uppercase + string.digits)
enc_charset = [None for _ in range(len(charset))]

print(charset)

txt = open('./cipher.py', 'r').read()
enc = open('./cipher.py.enc', 'r').read()

for i in range(len(txt)):
    c = txt[i]
    enc_c = enc[i]
    if c in charset:
        idx = charset.index(c)
        enc_charset[idx] = enc_c


charset = ''.join(charset)
enc_charset = ''.join([x if x is not None else '@' for x in enc_charset])

T = str.maketrans(enc_charset, charset)

with open('./flag.txt.enc', 'r') as f:
    enc_flag = f.read()
print(enc_flag.translate(T))

# Flag: AIS3{s0lving_sub5t1tuti0n_ciph3r_wi7h_kn0wn_p14int3xt_4ttack}
