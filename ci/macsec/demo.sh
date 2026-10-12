#!/bin/bash
# Local MACsec + Arnika demo.
#
# Builds an isolated three-namespace lab, runs the QKD KMS simulator and two
# Arnika nodes (macsec_netlink build), pushes an iperf3 TCP stream over MACsec,
# and prints once per second every key slot of both sides plus the receive rate
# and lost frames from the kernel's MACsec counters, so you can watch keys
# rotate under load.
#
#   adm-kms  (QKD simulator :18080)
#     |  192.168.100.0/30           |  192.168.101.0/30
#   adm-a ---- 10.0.0.0/30 (veth, Arnika UDP) ---- adm-b
#   adm-a macsec0 172.16.0.1 === MACsec ($CIPHER) === adm-b macsec0 172.16.0.2
#
# The host network is not touched; everything is removed on exit.
#
# Usage (root is required: the kernel only accepts MACsec SA changes with
# CAP_NET_ADMIN in the initial user namespace):
#   make build BUILD_TAGS=macsec_netlink BINARY_NAME=arnika-macsec
#   (cd tools && GOEXPERIMENT=runtimesecret go build -o ../build/qkd-simulator mock.go)
#   sudo DURATION=60 INTERVAL=10s CIPHER=gcm-aes-xpn-256 ci/macsec/demo.sh
set -euo pipefail

DURATION="${DURATION:-60}"      # iperf3 run time in seconds
INTERVAL="${INTERVAL:-10s}"     # Arnika key rotation interval
STARTUP_DELAY="${STARTUP_DELAY:-0}" # seconds between peer starts
CIPHER="${CIPHER:-gcm-aes-256}" # gcm-aes-256 or gcm-aes-xpn-256 (64-bit packet numbers)
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ARNIKA="${ARNIKA:-$ROOT/build/arnika-macsec}"
KMS="${KMS:-$ROOT/build/qkd-simulator}"
KMS_PORT=18080
NS_KMS=adm-kms NS_A=adm-a NS_B=adm-b

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)" >&2; exit 1; }
for f in "$ARNIKA" "$KMS"; do [ -x "$f" ] || { echo "missing binary: $f (see usage in $0)" >&2; exit 1; }; done
for c in ip iperf3; do command -v "$c" >/dev/null || { echo "missing tool: $c" >&2; exit 1; }; done
for ns in $NS_KMS $NS_A $NS_B; do
    if ip netns list | grep -qw "$ns"; then echo "namespace $ns already exists; remove it with: ip netns del $ns" >&2; exit 1; fi
done

WORK="$(mktemp -d /tmp/arnika-macsec-demo.XXXXXX)"
PIDS=()
cleanup() {
    set +e
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    for ns in $NS_KMS $NS_A $NS_B; do ip netns del "$ns" 2>/dev/null; done
    echo "Cleaned up namespaces. Logs kept in $WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

inns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

# --- topology -----------------------------------------------------------------
for ns in $NS_KMS $NS_A $NS_B; do ip netns add "$ns"; inns "$ns" ip link set lo up; done

link() { # link <nsX> <ifX> <addrX> <nsY> <ifY> <addrY>
    ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
    inns "$1" ip addr add "$3" dev "$2"; inns "$1" ip link set "$2" up
    inns "$4" ip addr add "$6" dev "$5"; inns "$4" ip link set "$5" up
}
link $NS_KMS kms-a 192.168.100.1/30 $NS_A a-kms 192.168.100.2/30
link $NS_KMS kms-b 192.168.101.1/30 $NS_B b-kms 192.168.101.2/30
link $NS_A a-b 10.0.0.1/30 $NS_B b-a 10.0.0.2/30

# SCI = underlay MAC + port 0001. A 256-bit suite because Arnika installs 32-byte keys.
SCI_A="$(inns $NS_A cat /sys/class/net/a-b/address | tr -d ':')0001"
SCI_B="$(inns $NS_B cat /sys/class/net/b-a/address | tr -d ':')0001"
inns $NS_A ip link add link a-b macsec0 type macsec sci "$SCI_A" cipher "$CIPHER" encrypt on
inns $NS_B ip link add link b-a macsec0 type macsec sci "$SCI_B" cipher "$CIPHER" encrypt on
inns $NS_A ip addr add 172.16.0.1/24 dev macsec0; inns $NS_A ip link set macsec0 up
inns $NS_B ip addr add 172.16.0.2/24 dev macsec0; inns $NS_B ip link set macsec0 up
echo "Lab up ($CIPHER): $NS_A macsec0 172.16.0.1 (SCI $SCI_A) <-> $NS_B macsec0 172.16.0.2 (SCI $SCI_B)"

# --- QKD simulator and Arnika -----------------------------------------------------
inns $NS_KMS env LISTEN=":$KMS_PORT" "$KMS" &> "$WORK/kms.log" & PIDS+=($!)
for _ in $(seq 1 20); do inns $NS_A bash -c "exec 3<>/dev/tcp/192.168.100.1/$KMS_PORT" 2>/dev/null && break; sleep 0.25; done

ARNIKA_PSK="$(head -c 32 /dev/urandom | base64)"   # shared secret for the UDP peer channel
start_node() { # start_node <ns> <id> <listen> <peer> <kms-ip> <sae> <rx-sci>
    inns "$1" env ARNIKA_ID="$2" LISTEN_ADDRESS="$3:9998" SERVER_ADDRESS="$4:9998" \
        INTERVAL="$INTERVAL" ARNIKA_PSK="$ARNIKA_PSK" \
        KMS_URL="http://$5:$KMS_PORT/api/v1/keys/$6" \
        MACSEC_INTERFACE=macsec0 MACSEC_RX_SCI="$7" \
        "$ARNIKA" &> "$WORK/arnika-$1.log" &
    PIDS+=($!)
}
# ARNIKA_IDs must differ in parity, otherwise both nodes pick the same role.
start_node $NS_A 9998 10.0.0.1 10.0.0.2 192.168.100.1 CONSB "$SCI_B"
sleep "$STARTUP_DELAY"
start_node $NS_B 9999 10.0.0.2 10.0.0.1 192.168.101.1 CONSA "$SCI_A"

echo -n "Waiting for the first key"
for _ in $(seq 1 60); do
    inns $NS_A ping -c1 -W1 172.16.0.2 &>/dev/null && break
    echo -n "."; sleep 1
done
if ! inns $NS_A ping -c1 -W1 172.16.0.2 &>/dev/null; then
    echo " no MACsec connectivity. Arnika logs:"; tail -n 20 "$WORK"/arnika-*.log; exit 1
fi
echo " MACsec traffic flows."

# --- load + live view ------------------------------------------------------------
inns $NS_B iperf3 -s -1 -B 172.16.0.2 &> "$WORK/iperf-server.log" & PIDS+=($!)
sleep 0.5
inns $NS_A iperf3 -c 172.16.0.2 -t "$DURATION" -i 1 --forceflush --logfile "$WORK/iperf.log" & IPERF=$!
PIDS+=($IPERF)

# All four key slots (AN 0-3) of one side, TX and RX, from `ip macsec show`.
# Each slot shows the first 4 hex digits of its key ID; "*" marks the encoding
# SA (the one TX encrypts with), "!" an SA that exists but is not active, and
# "...." an empty slot.
slots() {
    inns "$1" ip macsec show macsec0 | awk '
        /TXSC:/ { for (i = 1; i <= NF; i++) if ($i == "SA") enc = $(i + 1); sec = "tx"; next }
        /RXSC:/ { sec = "rx"; next }
        sec != "" && $1 ~ /^[0-3]:$/ {
            an = substr($1, 1, 1); k = ""; st = ""
            for (i = 1; i <= NF; i++) { if ($i == "key") k = substr($(i + 1), 1, 4); if ($i == "state") st = $(i + 1) }
            sub(/,$/, "", st)
            s[sec, an] = k (st == "on" ? "" : "!")
        }
        END {
            for (d = 1; d <= 2; d++) {
                sec = (d == 1 ? "tx" : "rx"); out = out sec
                for (an = 0; an < 4; an++) {
                    v = ((sec, an) in s) ? s[sec, an] : "...."
                    out = out sprintf(" %-6s", v ((sec == "tx" && an == enc) ? "*" : ""))
                }
                out = out (d == 1 ? " | " : "")
            }
            print out
        }'
}

# Frames the receiver dropped: InPktsLate + InPktsNotValid + InPktsNotUsingSA +
# InPktsUnusedSA of the RX SC (the row after the RX SC stats header).
rxdrops() {
    inns "$1" ip -s macsec show macsec0 | awk '
        /InOctetsValidated/ { hdr = 1; next }
        hdr { print $7 + $8 + $9 + $10; exit }
        END { if (!hdr) print 0 }'
}
rxbytes() { inns "$1" cat /sys/class/net/macsec0/statistics/rx_bytes; }

# Throughput and drops come from the kernel on the receiving side ($NS_B), not
# from iperf3's log, which is written in bursts and lags behind.
printf "\nslots: AN 0..3, value = key ID prefix, * = encoding SA, ! = inactive, .... = empty\n"
printf "rx rate and lost frames are measured on %s macsec0 over the last sample\n" "$NS_B"
printf "%-6s  %-61s  %-61s  %12s  %5s\n" "time" "$NS_A" "$NS_B" "rx rate" "lost"
last="" rotations=0 total_lost=0 zero=0 t0=$SECONDS
prev_bytes="$(rxbytes $NS_B)" prev_drops="$(rxdrops $NS_B)" prev_t="$(date +%s.%N)"
while kill -0 "$IPERF" 2>/dev/null; do
    sleep 1
    a="$(slots $NS_A)" b="$(slots $NS_B)"
    now_bytes="$(rxbytes $NS_B)" now_drops="$(rxdrops $NS_B)" now_t="$(date +%s.%N)"
    rate="$(awk -v b=$((now_bytes - prev_bytes)) -v t0="$prev_t" -v t1="$now_t" 'BEGIN { printf "%.2f Gbit/s", b * 8 / (t1 - t0) / 1e9 }')"
    lost=$((now_drops - prev_drops)); total_lost=$((total_lost + lost))
    [ "$now_bytes" -eq "$prev_bytes" ] && zero=$((zero + 1))
    prev_bytes=$now_bytes prev_drops=$now_drops prev_t=$now_t
    mark=""
    if [ -n "$last" ] && [ "$a" != "$last" ]; then mark="  <- slots changed"; rotations=$((rotations + 1)); fi
    last="$a"
    printf "%-6s  %-61s  %-61s  %12s  %5s%s\n" "+$((SECONDS - t0))s" "$a" "$b" "$rate" "$lost" "$mark"
done

# --- summary -----------------------------------------------------------------------
echo
echo "====== iperf3 ======"
grep -E 'sender|receiver' "$WORK/iperf.log" || tail -n 5 "$WORK/iperf.log"
echo "Slot changes seen on $NS_A: $rotations    samples with nothing received: $zero    frames lost at the MACsec receiver: $total_lost"
echo
echo "====== MACsec RX counters ($NS_B, receiving the iperf3 stream) ======"
echo "InPktsNotUsingSA / InPktsUnusedSA = frames that arrived for an SA the receiver did not have (yet)"
inns $NS_B ip -s macsec show macsec0 | sed -n '/RXSC/,$p'
