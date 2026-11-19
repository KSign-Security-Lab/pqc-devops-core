#!/bin/sh
# End-to-end smoke test for the example tools.
# usage: examples_smoke.sh EXAMPLES_DIR WORK_DIR
set -eu
B=$1
W=$2
rm -rf "$W" && mkdir -p "$W" && cd "$W"
fail() { echo "FAIL: $*" >&2; exit 1; }

printf abc > abc.txt
printf 'hello from sdc\n' > msg.txt

# hashsum: SHA-256("abc")
"$B/sdc_hashsum" abc.txt | grep -q '^ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ' \
    || fail "sdc_hashsum SHA-256"

# providers: lists every algorithm
"$B/sdc_providers" | grep -q '^AES-256-GCM ' || fail "sdc_providers"

# filecrypt: round trip, wrong password rejected
"$B/sdc_filecrypt" enc -i 1000 pw msg.txt msg.enc 2>/dev/null
"$B/sdc_filecrypt" dec pw msg.enc msg.dec
cmp -s msg.txt msg.dec || fail "sdc_filecrypt round trip"
if "$B/sdc_filecrypt" dec nope msg.enc x 2>/dev/null; then fail "wrong password accepted"; fi

# signtool: Ed25519 always available with a classical provider
"$B/sdc_signtool" keygen -a ed25519 s.pk s.sk
"$B/sdc_signtool" sign s.sk msg.txt msg.sig 2>/dev/null
"$B/sdc_signtool" verify s.pk msg.txt msg.sig >/dev/null || fail "sdc_signtool verify"
printf x >> msg.txt
if "$B/sdc_signtool" verify s.pk msg.txt msg.sig >/dev/null; then fail "tampered file verified"; fi

# PQC tools only when ML-KEM is available in this build
if "$B/sdc_providers" | grep -q '^ML-KEM-768 .* liboqs$'; then
    "$B/sdc_seal" keygen r.pk r.sk 2>/dev/null
    "$B/sdc_seal" seal r.pk msg.txt msg.sealed
    "$B/sdc_seal" open r.sk msg.sealed msg.opened
    cmp -s msg.txt msg.opened || fail "sdc_seal round trip"
    "$B/sdc_kex_demo" | grep -q 'keys match (hybrid)' || fail "sdc_kex_demo"
fi

echo "smoke: ok"
