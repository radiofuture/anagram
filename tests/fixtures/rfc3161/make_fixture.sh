#!/bin/sh
# Record an RFC 3161 fixture with the OpenSSL `ts` command. Offline, no network.
# The fixture shows that anagram.proofs.anchors.rfc3161 verifies tokens that a
# third-party TSA implementation made. Run from this directory:
#   sh make_fixture.sh
# Outputs: root.pem, tsa.pem, request.tsq, response.tsr, digest.hex
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat > "$work/ts.cnf" <<'EOF'
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
dir = .
serial = WORK/serial
signer_cert = WORK/tsa.pem
signer_key = WORK/tsa.key
certs = WORK/tsa.pem
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ess_cert_id_alg = sha256
ordering = no
tsa_name = no
ess_cert_id_chain = no
[ tsa_ext ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping
EOF
sed -i.bak "s|WORK|$work|g" "$work/ts.cnf"
echo 01 > "$work/serial"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/root.key" -out root.pem \
  -days 36500 -subj "/CN=Anagram Test Root CA" \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign"
openssl req -newkey rsa:2048 -nodes -keyout "$work/tsa.key" -out "$work/tsa.csr" \
  -subj "/CN=Anagram Test TSA"
openssl x509 -req -in "$work/tsa.csr" -CA root.pem -CAkey "$work/root.key" \
  -CAcreateserial -out "$work/tsa.pem" -days 36500 \
  -extfile "$work/ts.cnf" -extensions tsa_ext
cp "$work/tsa.pem" tsa.pem

printf 'anagram rfc3161 fixture' | openssl dgst -sha256 -binary | xxd -p -c 64 > digest.hex
openssl ts -query -sha256 -digest "$(cat digest.hex)" -cert -out request.tsq
openssl ts -reply -config "$work/ts.cnf" -queryfile request.tsq -out response.tsr
openssl ts -verify -in response.tsr -queryfile request.tsq -CAfile root.pem -untrusted tsa.pem
rm -f root.srl
