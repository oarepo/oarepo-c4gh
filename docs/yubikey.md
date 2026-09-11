Note on how to generate and upload a key to yubikey

```
openssl genpkey -algorithm X25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
ykman piv keys import --pin-policy NEVER --touch-policy NEVER 82 private.pem
```
