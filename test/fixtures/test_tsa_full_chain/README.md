This fixture contains a timestamp for the message `hello`, issued by a local
Sigstore timestamp-authority server.

`ts_chain.pem` contains the timestamping leaf followed by its self-signed root.
`response.tsr` embeds both certificates. There is no intermediate certificate.

The tests use the same response to check acceptance with its configured root and
rejection with the unrelated root from `../test_tsa/ts_chain.pem`. They also check
that the root is self-signed and the complete chain remains embedded, so replacing
the assets cannot silently remove the regression's precondition.

To regenerate the fixture, run these commands from the repository root. They
require OpenSSL, curl, Go, and make.

```bash
FIXTURE="$PWD/test/fixtures/test_tsa_full_chain"
WORK="$(mktemp -d)"
KEYS="$WORK/keys"
mkdir "$KEYS"

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 7300 \
  -keyout "$KEYS/root.key.pem" \
  -out "$KEYS/root.crt.pem" \
  -subj "/O=test/CN=Embedded Full Chain Test Root Certificate" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -keyout "$KEYS/tsa.key.pem" \
  -out "$KEYS/tsa.csr.pem" \
  -subj "/O=test/CN=Test TSA"

cat > "$KEYS/tsa.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF

openssl x509 -req -sha256 -days 7300 -set_serial 2 \
  -in "$KEYS/tsa.csr.pem" \
  -CA "$KEYS/root.crt.pem" \
  -CAkey "$KEYS/root.key.pem" \
  -extfile "$KEYS/tsa.ext" \
  -out "$KEYS/tsa.crt.pem"

cat "$KEYS/tsa.crt.pem" "$KEYS/root.crt.pem" > "$KEYS/ts_chain.pem"

timestamp-server serve \
  --port 3000 \
  --timestamp-signer=file \
  --timestamp-signer-hash=sha256 \
  --file-signer-key-path="$KEYS/tsa.key.pem" \
  --certificate-chain-path="$KEYS/ts_chain.pem" \
  --include-chain-in-response=true \
  --disable-ntp-monitoring=true &
TSA_PID=$!
trap 'kill "$TSA_PID"' EXIT

curl --fail --silent --show-error \
  http://localhost:3000/api/v1/timestamp/certchain \
  -o "$FIXTURE/ts_chain.pem"

printf 'hello' > "$KEYS/message"
openssl ts -query -data "$KEYS/message" -cert -sha512 \
  -out "$KEYS/request.tsq"
curl --fail --silent --show-error \
  -H "Content-Type: application/timestamp-query" \
  --data-binary @"$KEYS/request.tsq" \
  http://localhost:3000/api/v1/timestamp \
  -o "$FIXTURE/response.tsr"

kill "$TSA_PID"
trap - EXIT
```
