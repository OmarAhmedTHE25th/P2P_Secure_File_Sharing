#!/usr/bin/env bash
# End-to-end test with four separate identities talking over real TLS on localhost:
#   alice receives. bob, carol and mallory send.
#   alice trusts bob and carol (not mallory). bob and mallory trust alice. carol trusts nobody.
#
# Usage: bash scripts/e2e_test.sh <path-to-P2P_Secure_File_Sharing-executable>
# Needs python3 (raw sockets and a hand-made TLS client).
set -uo pipefail

if [[ $# -ne 1 || ! -x "$1" ]]; then
    echo "Usage: $0 <path-to-executable>" >&2
    exit 2
fi

exe="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
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

# ---- everyone gets their own identity, in their own folder ----
for person in alice bob carol mallory; do
    mkdir -p "$work/$person"
    (cd "$work/$person" && "$exe" init "$person" > /dev/null) || { echo "could not create the identity for $person"; exit 2; }
done
fingerprint_of() { (cd "$work/$1" && "$exe" fingerprint | sed 's/^Your fingerprint: //'); }
trust() { (cd "$work/$1" && "$exe" trust add "$(fingerprint_of "$2")" "$2" > /dev/null); }   # $1 trusts $2

trust alice bob
trust alice carol
trust bob alice
trust mallory alice

( cd "$work/alice" && exec "$exe" receive "$port" received ) > "$work/receiver.log" 2>&1 &
receiver_pid=$!
for _ in $(seq 1 50); do
    grep -q "Listening on port" "$work/receiver.log" 2>/dev/null && break
    sleep 0.1
done
grep -q "Listening on port" "$work/receiver.log" || { echo "receiver did not start:"; cat "$work/receiver.log"; exit 1; }

head -c 500000 /dev/urandom > "$work/bob/big.bin"
printf 'x' > "$work/bob/one.txt"
: > "$work/bob/empty.txt"
head -c 1000 /dev/urandom > "$work/bob/with space.bin"
printf 'x' > "$work/bob/CON.txt"
echo "hello from carol" > "$work/carol/carol.txt"
echo "hello from mallory" > "$work/mallory/mallory.txt"
echo "revoke me" > "$work/bob/r1.txt"

# send <who> <file>  -> sets $out (what the sender printed) and $code (exit code; 124 means it hung)
send() {
    out="$(cd "$work/$1" && timeout 20 "$exe" send localhost "$port" "$2" 2>&1)"
    code=$?
    if [[ $code -eq 124 ]]; then
        fail "the sender hung for 20 seconds instead of exiting ($2)"
    fi
    if grep -qE "Sanitizer|runtime error" <<< "$out"; then
        fail "sanitizer report in the sender's output for $2: $out"
    fi
}
sent_ok() { [[ $code -eq 0 ]] && grep -q "file verified and saved" <<< "$out"; }

echo "End-to-end test on port $port (four separate identities)"

echo "A trusted sender:"
for f in big.bin one.txt empty.txt "with space.bin"; do
    send bob "$f"
    if ! sent_ok; then
        fail "$f: transfer did not succeed. Sender said: $out"
    elif ! cmp -s "$work/bob/$f" "$work/alice/received/$f"; then
        fail "$f: file arrived but does not match the original"
    else
        pass "$f transferred and verified (byte-identical)"
    fi
done
grep -q "Authenticated peer 'bob'" "$work/receiver.log" && pass "the receiver knows the sender by name (bob)" || fail "receiver did not log bob's name"

send bob big.bin
if grep -q "already exists" <<< "$out"; then pass "sending the same file twice is refused"; else fail "duplicate was not refused: $out"; fi

send bob CON.txt
if grep -q "filename not allowed" <<< "$out"; then pass "reserved filename CON.txt is refused"; else fail "CON.txt was not refused: $out"; fi
if [[ -e "$work/alice/received/CON.txt" ]]; then fail "CON.txt was written to disk anyway"; else pass "refused file never touched the disk"; fi
if ls "$work"/alice/received/*.part >/dev/null 2>&1; then fail "leftover .part files in received/"; else pass "no leftover .part files"; fi

echo "Who is allowed in:"
send mallory mallory.txt
if sent_ok; then
    fail "a sender the receiver does not trust got a file through"
elif [[ $code -eq 0 ]]; then
    fail "a refused sender exited with status 0, as if it had worked"
elif [[ -e "$work/alice/received/mallory.txt" ]]; then
    fail "a refused sender's file was written to disk"
elif ! grep -q "$(fingerprint_of mallory)" "$work/receiver.log"; then
    fail "the receiver did not log the refused sender's fingerprint"
elif ! grep -q "may not trust you yet" <<< "$out"; then
    fail "the refused sender was not told what probably happened: $out"
else
    pass "a sender the receiver does not trust is refused (and everyone is told how to fix it)"
fi

send carol carol.txt
if sent_ok; then
    fail "a sender sent to a receiver it does not trust"
elif ! grep -q "not in your trust list" <<< "$out" || ! grep -q "$(fingerprint_of alice)" <<< "$out"; then
    fail "the sender did not refuse the unknown receiver, or did not show its fingerprint: $out"
elif grep -q "Incoming file: carol.txt" "$work/receiver.log"; then
    fail "data was sent to a receiver the sender does not trust"
else
    pass "a sender refuses a receiver it does not trust, before sending anything"
fi

(cd "$work/alice" && "$exe" trust remove bob > /dev/null)
send bob r1.txt
if sent_ok; then fail "bob still got in after being removed from the trust list"; else pass "removing a peer cuts them off at once, without restarting the receiver"; fi
if kill -0 "$receiver_pid" 2>/dev/null; then pass "the receiver kept running"; else fail "the receiver died"; fi
trust alice bob
send bob r1.txt
if sent_ok && cmp -s "$work/bob/r1.txt" "$work/alice/received/r1.txt"; then pass "trusting bob again lets him back in"; else fail "bob could not get back in: $out"; fi

echo "Protocol behavior:"
tls_result="$(timeout 40 python3 - "$port" "$work/bob" 2>&1 <<'PY'
import socket, ssl, struct, sys
port = int(sys.argv[1])
bob = sys.argv[2]

def client_context(version):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(bob + "/identity.crt", bob + "/identity.key")   # a trusted identity
    ctx.minimum_version = version
    ctx.maximum_version = version
    return ctx

# 1) A TLS 1.2 client must be refused, even with a trusted identity
try:
    s = socket.create_connection(("localhost", port), timeout=5)
    t = client_context(ssl.TLSVersion.TLSv1_2).wrap_socket(s, server_hostname="localhost")
    t.close()
    print("a TLS 1.2 client was accepted")
    sys.exit(1)
except (ssl.SSLError, OSError):
    pass

# 2) Right bytes but a wrong hash in the header: must end in HASH_MISMATCH and keep nothing
def read_exact(t, n):
    data = b""
    while len(data) < n:
        chunk = t.recv(n - len(data))
        if not chunk:
            raise OSError("connection closed early")
        data += chunk
    return data

def read_ack(t):
    read_exact(t, 47)
    return read_exact(t, 1)[0]

try:
    s = socket.create_connection(("localhost", port), timeout=10)
    t = client_context(ssl.TLSVersion.TLSv1_3).wrap_socket(s, server_hostname="localhost")
    name, data = b"tampered.txt", b"hello tampered world"
    t.sendall(struct.pack(">BIQH32s", 1, len(name), len(data), len(name), b"\xAA" * 32) + name)
    first = read_ack(t)
    t.sendall(data)
    t.sendall(struct.pack(">B46x", 3))
    final = read_ack(t)
    t.close()
except Exception as e:
    print("hash test failed: %r" % (e,))
    sys.exit(1)
if first != 3 or final != 1:
    print("expected READY(3) then HASH_MISMATCH(1), got %d then %d" % (first, final))
    sys.exit(1)
print("ok")
PY
)"
if [[ "$tls_result" == "ok" ]]; then
    pass "a TLS 1.2 client is refused, and a wrong hash is caught (HASH_MISMATCH)"
else
    fail "protocol checks: $tls_result"
fi
if [[ -e "$work/alice/received/tampered.txt" || -e "$work/alice/received/tampered.txt.part" ]]; then
    fail "a file with a wrong hash was kept on disk"
else
    pass "the file with the wrong hash left nothing on disk"
fi

echo "Connection limits (this part takes about 12 seconds)"
# MAX must match ServerNode::MAX_CONNECTIONS in server_node.hpp.
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
if grep -qE "Sanitizer|runtime error" "$work/receiver.log"; then fail "sanitizer report in the receiver log"; fi

if [[ $failures -eq 0 ]]; then
    echo "ALL END-TO-END CHECKS PASSED"
    exit 0
fi
echo "$failures check(s) failed. Receiver log:"
cat "$work/receiver.log"
exit 1
