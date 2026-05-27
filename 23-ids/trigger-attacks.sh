#!/usr/bin/env bash
#
# trigger-attacks.sh — Chapter 23 traffic generator (the "attacker").
#
# Generates the loopback traffic that trips each IDS rule. Run the IDS in one
# terminal, this in another:
#
#   terminal 1:   sudo ./ids                 # the detector
#   terminal 2:   ./trigger-attacks.sh       # the attacker (no sudo needed)
#
# Pick what to fire (default: all):
#   ./trigger-attacks.sh [all|beacon|scan|susp] [host]
#
# host defaults to 127.0.0.1. Tunables via env: PORT, COUNT, INTERVAL,
# SCAN_LO, SCAN_HI. Only tool used is nc.
#
set -uo pipefail          # NOT -e: nc -z exits non-zero on refused ports

WHAT="${1:-all}"
HOST="${2:-127.0.0.1}"

PORT="${PORT:-9999}"        # beacon destination port
COUNT="${COUNT:-7}"         # beacon callbacks (need >~6 for the rule to judge)
INTERVAL="${INTERVAL:-4}"   # seconds between beacon callbacks
SCAN_LO="${SCAN_LO:-9000}"  # port-scan range start
SCAN_HI="${SCAN_HI:-9080}"  # port-scan range end

# Ports the IDS flags by signature (must match the suspicious[] list in ids.c).
SUSP_PORTS=(1337 4444 5555 6667 12345 31337 50050)

command -v nc >/dev/null || { echo "nc not found — install netcat."; exit 1; }

# One UDP datagram via bash /dev/udp — the send is instant, so beacon spacing is
# exactly the sleep in fire_beacon (no nc -w timeout jitter, which the rule needs).
udp1() { printf 'ping' > "/dev/udp/$HOST/$1" 2>/dev/null; }
tcp1() { nc -z -w1 "$HOST" "$1" >/dev/null 2>&1; }            # one TCP connect

fire_susp() {
    echo "[susp]   one packet to each known-C2 port on $HOST ..."
    for p in "${SUSP_PORTS[@]}"; do
        echo "         -> $HOST:$p"
        udp1 "$p"
    done
}

fire_scan() {
    local n=$((SCAN_HI - SCAN_LO + 1))
    echo "[scan]   TCP connect to $n ports ($SCAN_LO-$SCAN_HI) on $HOST ..."
    for p in $(seq "$SCAN_LO" "$SCAN_HI"); do tcp1 "$p"; done
    echo "         done (expect a port-scan alert)."
}

fire_beacon() {
    echo "[beacon] $COUNT UDP callbacks to $HOST:$PORT every ${INTERVAL}s (be patient) ..."
    for i in $(seq "$COUNT"); do
        echo "         callback $i/$COUNT -> $HOST:$PORT"
        udp1 "$PORT"
        [ "$i" -lt "$COUNT" ] && sleep "$INTERVAL"
    done
    echo "         done (expect a beacon alert)."
}

case "$WHAT" in
    susp|suspicious) fire_susp ;;
    scan|portscan)   fire_scan ;;
    beacon)          fire_beacon ;;
    all)             fire_susp; echo; fire_scan; echo; fire_beacon ;;
    *) echo "usage: $0 [all|beacon|scan|susp] [host]"; exit 2 ;;
esac

echo "Triggers sent. Watch the IDS terminal for alerts."
