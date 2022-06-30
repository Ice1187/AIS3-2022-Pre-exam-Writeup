import sys
from Crypto.Util.number import inverse

# Check login


def check():
    a = int.from_bytes(sys.argv[1].encode(), 'big')
    b = pow(a, 65537, 542732316977950510497270190501021791757395568139126739977487019184541033966691938940926649138411381198426866278991473)
    # print(b)
    if b == 451736263303355935449028567064392382249020023967373174925770068593206982683303653948838172763093279548888815048027759:
        print('Good')
    else:
        print('Bad')


# RSA-like solution
n = 542732316977950510497270190501021791757395568139126739977487019184541033966691938940926649138411381198426866278991473
r = n-1
e = 65537
d = inverse(e, r)
c = 451736263303355935449028567064392382249020023967373174925770068593206982683303653948838172763093279548888815048027759
m = pow(c, d, n)
flag = m.to_bytes(64, 'big').strip(b'\x00').decode()
flag = 'AIS3{' + flag

print(flag)

# Flag: AIS3{from_rop_to_python_to_pickle_to_math}