Test:

```
curl -sL -w "%{http_code}\n"  http://localhost -o /dev/null --user test:foobar
```
