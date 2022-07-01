flags = ['AIS3{', 'good', 'luck', 'finding', 'the', 'flags', 'value', 'using', 'strings',
         'command', 'guess', 'which', 'substring', 'is', 'our', 'actual', 'answer', 'lmaoo', '}']
indexes = [0, 0x4, 0x10, 0xd, 0xa, 0x4, 0x8, 0x7, 0x1, 0x2, 0x12]

flag = []
for i in indexes:
    flag.append(flags[i])

print('_'.join(flag))

# Flag: AIS3{_the_answer_is_guess_the_strings_using_good_luck_}
