#!/usr/bin/env bash
# End-to-end test: starts a real receiver, sends files to it over TLS on localhost,
# then checks what arrived (and what was refused).
#
# Usage: bash scripts/e2e_test.sh <path-to-P2P_Secure_File_Sharing-executable>
set -uo pipefail

if [[ $# -ne 1 || ! -x "$1" ]]; then
    echo "Usage: $0 <path-to-executable>" >&2
    exit 2
fi

exe="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
port=$((20000 + RANDOM % 20000))
receiver_pid=""
failures=0

cleanup() {
    if [[ -n "$receiver_pid" ]]; then kill "$receiver_pid" 2>/dev/null; fi
    rm -rf "$work"
}
trap cleanup EXIT

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }

mkdir -p "$work/node"
cd "$work/node" || exit 2
CERT_DIR="$work/node" bash "$here/gen_certs.sh" >/dev/null || { echo "could not generate certs"; exit 2; }

"$exe" receive "$port" received > receiver.log 2>&1 &
receiver_pid=$!
for _ in $(seq 1 50); do
    grep -q "Listening on port" receiver.log 2>/dev/null && break
    sleep 0.1
done
grep -q "Listening on port" receiver.log || { echo "receiver did not start:"; cat receiver.log; exit 1; }

head -c 500000 /dev/urandom > big.bin
printf 'x' > one.txt
: > empty.txt
head -c 1000 /dev/urandom > "with space.bin"
printf 'x' > CON.txt

# send <file>  -> sets $out (client output) and $code (exit code). timeout 124 means the client hung.
send() {
    out="$(timeout 20 "$exe" send localhost "$port" "$1" 2>&1)"
    code=$?
    if grep -qE "Sanitizer|runtime error" <<< "$out"; then
        fail "sanitizer report in the client output for $1: $out"
    fi
}

echo "End-to-end test on port $port"

for f in big.bin one.txt empty.txt "with space.bin"; do
    send "$f"
    if [[ $code -eq 124 ]]; then
        fail "$f: client never exited (watchdog timer not cancelled?)"
    elif [[ $code -ne 0 ]] || ! grep -q "file verified and saved" <<< "$out"; then
        fail "$f: transfer did not succeed. Client said: $out"
    elif ! cmp -s "$f" "received/$f"; then
        fail "$f: file arrived but does not match the original"
    else
        pass "$f transferred and verified (byte-identical)"
    fi
done

send big.bin
if grep -q "already exists" <<< "$out"; then pass "sending the same file twice is refused"; else fail "duplicate was not refused: $out"; fi

send CON.txt
if grep -q "filename not allowed" <<< "$out"; then pass "reserved filename CON.txt is refused"; else fail "CON.txt was not refused: $out"; fi

if [[ -e received/CON.txt ]]; then fail "CON.txt was written to disk anyway"; else pass "refused file never touched the disk"; fi

if ls received/*.part >/dev/null 2>&1; then fail "leftover .part files in received/"; else pass "no leftover .part files"; fi

echo "Connection limits (this part takes about 12 seconds)"
# Needs python3 for raw sockets. MAX must match ServerNode::MAX_CONNECTIONS in server_node.hpp.
limits_result="$(timeout 60 python3 - "$port" 2>&1 <<'PY'
import socket, sys, time
port = int(sys.argv[1])
MAX = 64

def closed_by_peer(s):
    s.setblocking(False)
    try:
        return s.recv(1) == b''
    except BlockingIOError:
        return False
    except OSError:
        return True

# 1) More connections than seats: the first MAX are kept, the extras are dropped at once
socks = [socket.create_connection(('localhost', port)) for _ in range(MAX + 6)]
time.sleep(1.5)
kept = sum(1 for s in socks[:MAX] if not closed_by_peer(s))
dropped = sum(1 for s in socks[MAX:] if closed_by_peer(s))
for s in socks:
    s.close()
if kept != MAX or dropped != 6:
    print(f"connection limit: {kept}/{MAX} kept, {dropped}/6 extras dropped")
    sys.exit(1)
time.sleep(1)

# 2) A peer that connects and never says anything gets hung up on
s = socket.create_connection(('localhost', port))
start = time.time()
while time.time() - start < 15:
    if closed_by_peer(s):
        break
    time.sleep(0.2)
else:
    print("a silent peer was not hung up on within 15 seconds")
    sys.exit(1)
print("ok")
PY
)"
if [[ "$limits_result" == "ok" ]]; then
    pass "connections beyond the limit are dropped, and a silent peer is hung up on"
else
    fail "connection limits: $limits_result"
fi

# Did anything crash or trip a sanitizer along the way? (sanitizer builds print these)
if ! kill -0 "$receiver_pid" 2>/dev/null; then fail "the receiver process died during the test"; fi
if grep -qE "Sanitizer|runtime error" receiver.log; then fail "sanitizer report in the receiver log"; fi

if [[ $failures -eq 0 ]]; then
    echo "ALL END-TO-END CHECKS PASSED"
    exit 0
fi
echo "$failures check(s) failed. Receiver log:"
cat receiver.log
exit 1
