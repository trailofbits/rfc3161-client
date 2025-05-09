The timestamp responses in this directory were generated 
* with CLI tool from  https://github.com/sigstore/timestamp-authority/ 
* using the timestamp.sigstage.dev TSA (The relevant certificates can be
  found in ./ts_chain.pem)

```bash
echo -n "hello" > f
for HASH in sha256 sha384 sha512; do
  ./bin/timestamp-cli --timestamp_server https://timestamp.sigstage.dev/ timestamp --artifact f --hash $HASH --out response-$HASH.tsr
done
```
