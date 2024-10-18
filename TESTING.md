# Creating a Request

```shell
openssl ts -query -data README.md -no_nonce -sha512 -cert -out file.tsq
```

# Updating fixtures

As we use `Sigstore TSA`](https://github.com/sigstore/timestamp-authority), 
we generate the fixture against it.

Download the binaries or build them and run the server.


## Run the script
```shell
# Warning, this requires rfc3161-client, which is not yet available
uv run scripts/update_fixtures.py
```