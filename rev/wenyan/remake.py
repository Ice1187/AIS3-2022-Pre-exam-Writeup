def ying2(charCode, n):
    return (charCode - (charCode % n)) / n


def xue1(charCode, n):
    ret = 0
    b = 1
    while True:
        if charCode <= 0 or n <= 0:
            break
        if (charCode % 2 == 1) and (n % 2 == 1):
            ret += b
        charCode = ying2(charCode)(2)
        n = ying2(n)(2)
        b = b * 2
    return ret


def check(cmd):
    s = ''
    i = 0
    while True:
        if i >= len(cmd):
            return
        charCode = cmd[i]
        if len(cmd) - i >= 2:
            charCode2 = cmd[i+1]
        if len(cmd) - i > 2:
            charCode3 = cmd[i+2]
