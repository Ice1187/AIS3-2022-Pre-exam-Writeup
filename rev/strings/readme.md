1. Trim the input.
2. Split the trimmed input by `_`, then store into a `vec`.
3. Check the length of `vec` is 11.
4. We can see 11 index in the memory while `memcpy`, I guess that could be the substring index for the flag.

```
0x5555555991d0: 0x0000000000000000      0x0000000000000004
0x5555555991e0: 0x0000000000000010      0x000000000000000d
0x5555555991f0: 0x000000000000000a      0x0000000000000004
0x555555599200: 0x0000000000000008      0x0000000000000007
0x555555599210: 0x0000000000000001      0x0000000000000002
0x555555599220: 0x0000000000000012      0x6f6f677b33534941
```

5. Use `solve.py` to extract the guess flag.
