from PIL import Image

# ref: https://stackoverflow.com/questions/53364769/get-frames-per-second-of-a-gif-in-python

im = Image.open('./gift_in_the_dream_updated.gif')

flag = ''
try:
    while 1:
        flag += chr(im.info['duration'] // 10)
        im.seek(im.tell()+1)
except EOFError:
    pass

print(flag)

# Flag: AIS3{5T3g4n0gR4pHy_c4N_b3_fUn_s0m37iMe}
