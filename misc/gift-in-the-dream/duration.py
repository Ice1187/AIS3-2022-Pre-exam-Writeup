from PIL import Image

# ref: https://stackoverflow.com/questions/53364769/get-frames-per-second-of-a-gif-in-python

im = Image.open('./gift_in_the_dream_updated.gif')

flag = ''
try:
    while 1:
        print(im.info['duration'])
        im.seek(im.tell()+1)
except EOFError:
    pass


# Flag: AIS3{5T3g4n0gR4pHy_c4N_b3_fUn_s0m37iMe}
