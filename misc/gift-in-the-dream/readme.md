1. By `strings` the image, it gives a hint about the frame duration.

```
$ strings gift_in_the_dream_updated.gif | head
GIF89a
Qwhy is the animation lagging? why is the duration so weird? is this just a dream?
NETSCAPE2.0
```

2. So write a script to get the duration info of each frame and covert it to ASCII.

Flag: `Flag: AIS3{5T3g4n0gR4pHy_c4N_b3_fUn_s0m37iMe}`
