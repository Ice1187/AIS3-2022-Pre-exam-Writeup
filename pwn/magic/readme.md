1. read is hijacked to do some extra work. The extra code starts at `0x401d06` in gdb:

```
   0x401d06    push   rax
   0x401d07    push   rdi
   0x401d08    push   rsi
   0x401d09    push   rdx
   0x401d0a    mov    rax, 1
   0x401d11    mov    rdi, 0
   0x401d18    mov    rsi, 0x404f20
   0x401d1f    mov    rdx, 5
   0x401d26    syscall              // write(stdout, 0x404f20, 5)
   0x401d28    pop    rdx
   0x401d29    pop    rsi
   0x401d2a    pop    rdi
   0x401d2b    pop    rax
   0x401d2c    mov    rax, 0x404f00
   0x401d33    add    qword ptr [rax], 1
   0x401d37    mov    rax, qword ptr [rax]
   0x401d3a    mov    rbx, 0x404f08
   0x401d41    mov    rbx, qword ptr [rbx]
   0x401d44    mov    r8, 0x404f10          // original read
   0x401d4b    mov    r8, qword ptr [r8]
   0x401d4e    cmp    rax, 0xe     // check: [0x404f00] == 0xe
   0x401d52    jne    0x401d61
   0x401d54    cmp    rbx,0x8      // check: [0x404f08] == 0x8
   0x401d58    jne    0x401d61
   0x401d5a    mov    rdx,0x1000
   0x401d61    jmp    r8
```

2. Write has a similar code:

```
   0x401e00    push   rax
   0x401e01    push   rdi
   0x401e02    push   rsi
   0x401e03    push   rdx
   0x401e04    mov    rax,0x1
   0x401e0b    mov    rdi,0x0
   0x401e12    mov    rsi,0x404f28
   0x401e19    mov    rdx,0x5
   0x401e20    syscall
   0x401e22    pop    rdx
   0x401e23    pop    rsi
   0x401e24    pop    rdi
   0x401e25    pop    rax
   0x401e26    mov    rax,0x404f08
   0x401e2d    add    QWORD PTR [rax],0x1
   0x401e31    mov    rax,QWORD PTR [rax]
   0x401e34    mov    rbx,0x404f00
   0x401e3b    mov    rbx,QWORD PTR [rbx]
   0x401e3e    mov    r8,0x404f18
   0x401e45    mov    r8,QWORD PTR [r8]
   0x401e48    cmp    rax,0x3
   0x401e4c    jne    0x401e5b
   0x401e4e    cmp    rbx,0x7
   0x401e52    jne    0x401e5b
   0x401e54    mov    rdx,0x100
   0x401e5b    jmp    r8
```

3. When call r/w == 3/8 times, we can write 0x1000 bytes, when call r/w == 2/3 times, we can read 0x100 bytes.
   - `[0x404f00]` counts how many time read been called
   - `[0x404f08]` counts how many time write been called
   - `[0x404f10]` original read
   - `[0x404f18]` original write
4. Use super read to leak libc address. The version of glibc can be obtained from the docker container.
5. Use super write to do ret2libc.

Flag: `AIS3{ma4a4a4aGiCian}`