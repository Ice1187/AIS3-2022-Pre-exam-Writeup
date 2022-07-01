# from chal/xl/macrosheets/sheet1.xml
a = '''
FORMULA(mqLen!D14&amp;Mment!BA10&amp;coCGA!S17&amp;coCGA!Q19&amp;KRnsl!L19&amp;Mment!F3&amp;coCGA!G26&amp;coCGA!O23&amp;coCGA!P3&amp;coCGA!K12&amp;KRnsl!J19&amp;KRnsl!C11&amp;coCGA!N3&amp;mqLen!E4&amp;coCGA!D11&amp;KRnsl!T5&amp;JVHco!K10&amp;mqLen!BA14&amp;Mment!W1&amp;KRnsl!U13&amp;KRnsl!V9&amp;mqLen!C12&amp;KRnsl!J4&amp;Mment!Y19&amp;mqLen!K19&amp;JVHco!F2&amp;mqLen!K10&amp;coCGA!Z15&amp;mqLen!N21&amp;Mment!N1&amp;Mment!S2&amp;coCGA!X2&amp;Mment!D16&amp;coCGA!U26&amp;coCGA!R1&amp;mqLen!V9&amp;mqLen!R11&amp;Mment!X1&amp;coCGA!D5&amp;KRnsl!Z19&amp;mqLen!BA4&amp;coCGA!Z9&amp;coCGA!G7&amp;mqLen!U10&amp;Mment!U11&amp;coCGA!G18&amp;JVHco!V1&amp;mqLen!O26&amp;Mment!G5&amp;KRnsl!H22&amp;Mment!P10&amp;JVHco!W17&amp;Mment!F8&amp;coCGA!L15&amp;coCGA!H3&amp;KRnsl!U17&amp;KRnsl!BA11&amp;coCGA!X12&amp;KRnsl!F14&amp;Mment!B10&amp;KRnsl!V12&amp;Mment!U12&amp;coCGA!P14&amp;coCGA!Y1&amp;JVHco!B10&amp;JVHco!F16&amp;KRnsl!Q26&amp;Mment!P25&amp;KRnsl!M3&amp;KRnsl!I26&amp;mqLen!L15&amp;mqLen!V25&amp;KRnsl!G2&amp;Mment!I18&amp;Mment!M4&amp;KRnsl!C7&amp;JVHco!N5&amp;KRnsl!M19&amp;Mment!J9&amp;Mment!I7&amp;coCGA!G13&amp;KRnsl!M12&amp;mqLen!X2&amp;mqLen!M1&amp;JVHco!P3&amp;KRnsl!S12&amp;Mment!U10&amp;JVHco!D16&amp;mqLen!P17&amp;KRnsl!I5&amp;coCGA!W24&amp;JVHco!E10&amp;Mment!B8&amp;coCGA!C14&amp;JVHco!Z15&amp;Mment!BA11&amp;coCGA!F19&amp;KRnsl!Z2&amp;JVHco!D13&amp;Mment!O2&amp;KRnsl!D19&amp;Mment!K19&amp;Mment!U20&amp;JVHco!Q9&amp;KRnsl!I17&amp;coCGA!X17&amp;JVHco!Q24&amp;KRnsl!Q4&amp;coCGA!N21&amp;coCGA!W11&amp;JVHco!E17&amp;mqLen!H19&amp;KRnsl!X6&amp;coCGA!N26&amp;coCGA!N18&amp;KRnsl!Q17&amp;JVHco!J25&amp;KRnsl!Z16&amp;mqLen!P13&amp;coCGA!Z21&amp;JVHco!C24&amp;Mment!X19&amp;Mment!O21,A137)
'''.strip()
a = a[8:-6]
a = a.replace('&amp;', '&')
a = a.split('&')

# hardcore...
flag = ''
for i in a:
    c = input(f'{i} >')
    if c.isnumeric():
        c = chr(int(c))
    flag += c
print(flag)

# Flag: AIS3{XLM_iS_to0_o1d_but_co0o0o00olll!!}
