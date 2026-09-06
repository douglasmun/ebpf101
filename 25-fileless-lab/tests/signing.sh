#!/bin/bash
set -x
cd /work
echo "=== BLOCK 20: openssl CA + leaf signer pipeline (verbatim commands) ==="
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout org-ca.key -out org-ca.crt -days 3650 -nodes -subj "/CN=Org Binary-Authz CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
echo "CA EXIT=$?"

openssl x509 -in org-ca.crt -outform DER -out org-ca.der; echo "DER EXIT=$?"

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout sign.key -out sign.csr -subj "/CN=fileless-gate signer 2026-Q3"
echo "CSR EXIT=$?"

openssl x509 -req -in sign.csr -CA org-ca.crt -CAkey org-ca.key -CAcreateserial \
    -days 180 -out sign.crt -extfile <(printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning")
echo "LEAF EXIT=$?"

openssl x509 -in sign.crt -outform DER -out sign.der; echo "DER2 EXIT=$?"
set +x
echo
echo "=== verify the chain actually validates ==="
openssl verify -CAfile org-ca.crt sign.crt
echo "verify exit=$?"
echo
echo "=== leaf cert contents ==="
openssl x509 -in sign.crt -noout -subject -issuer -ext keyUsage,extendedKeyUsage 2>&1
