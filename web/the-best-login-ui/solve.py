import readline
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
    print(res.text)
    return res.text


'''
while True:
    data = input('data> ')
    res = naive_req(data)
'''

flag = 'username=admin&password=AIS3{Bl1nd-b4s3d r3gex n0sq1i?! (:3[___]}'
naive_req(flag)

# Flag: AIS3{Bl1nd-b4s3d r3gex n0sq1i?! (:3[___]}
