#!/usr/bin/env bash
#
# verify-ids.sh — Chapter 23 hands-free demo.
#
# Loads the IDS on lo, then generates loopback traffic that trips each of the
# three detection rules in turn, and stops it. No second terminal needed.
#
#   1. suspicious port — one UDP datagram to 4444 (Metasploit default)
#   2. port scan       — TCP connect to 81 ports (9000-9080) in a burst
#   3. beacon          — 7 regularly-spaced UDP callbacks to 9999 (~4s apart)
#
# The beacon needs several regular samples, so this runs for ~30s.
#
# Run:  sudo bash 23-ids/verify-ids.sh
#
# Needs root (raw socket + loading BPF). nc is the only traffic tool used.
#
set -uo pipefail          # NOT -e: nc -z returns non-zero on refused ports

cd "$(dirname "$0")"

if [[ ! -x ./ids ]]; then
    echo "./ids not built. Run 'make' in 23-ids/ first."
    exit 1
fi

echo "Starting IDS on lo (alerts print below as they fire) ..."
./ids lo &
P=$!
sleep 2

# UDP datagrams go via bash /dev/udp: the send is instant, so beacon spacing is
# exactly the sleep below (no nc timeout jitter — which is what the rule needs).
echo "[trigger] suspicious port -> 127.0.0.1:4444"
printf 'x' > /dev/udp/127.0.0.1/4444 2>/dev/null

echo "[trigger] port scan -> 127.0.0.1:9000-9080"
for p in $(seq 9000 9080); do nc -z -w1 127.0.0.1 "$p" >/dev/null 2>&1; done

echo "[trigger] beacon -> 127.0.0.1:9999, 7 callbacks exactly 3s apart (be patient) ..."
for i in $(seq 7); do
    printf 'ping' > /dev/udp/127.0.0.1/9999 2>/dev/null
    sleep 3
done

sleep 1
echo "Stopping IDS ..."
kill -INT "$P" 2>/dev/null
wait "$P" 2>/dev/null
