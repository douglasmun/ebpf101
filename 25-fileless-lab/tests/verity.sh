#!/bin/bash
cd /work
# Key material (block 20) — generated here so this test is self-contained.
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout org-ca.key -out org-ca.crt -days 3650 -nodes -subj "/CN=Org Binary-Authz CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout sign.key -out sign.csr -subj "/CN=fileless-gate signer" >/dev/null 2>&1
openssl x509 -req -in sign.csr -CA org-ca.crt -CAkey org-ca.key -CAcreateserial \
  -days 180 -out sign.crt \
  -extfile <(printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning") >/dev/null 2>&1
echo "=== kernel fs-verity support ==="
grep -i verity /proc/filesystems 2>/dev/null
zcat /proc/config.gz 2>/dev/null | grep -i FS_VERITY || echo "(no /proc/config.gz)"
echo
echo "=== try the doc's per-binary steps on a real file ==="
cp /bin/true /work/foo 2>/dev/null || cp hello /work/foo
echo "--- fsverity enable /work/foo   (fs=$(stat -f -c %T /work/foo))"
fsverity enable /work/foo; echo "  exit=$?"
echo
echo "--- fsverity sign (needs the digest, key + cert from block 20)"
fsverity sign /work/foo foo.p7 --key sign.key --cert sign.crt; echo "  exit=$?"
ls -l foo.p7 2>/dev/null
echo
echo "--- setfattr user.org.sig"
setfattr -n user.org.sig -v "0x$(xxd -p foo.p7 2>/dev/null | tr -d '\n')" /work/foo; echo "  exit=$?"
getfattr -d -m . /work/foo 2>&1 | head -3
