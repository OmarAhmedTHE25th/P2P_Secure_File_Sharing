# P2P Secure File Sharing

[![CI](https://github.com/OmarAhmedTHE25th/P2P_Secure_File_Sharing/actions/workflows/ci.yml/badge.svg)](https://github.com/OmarAhmedTHE25th/P2P_Secure_File_Sharing/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)

A peer-to-peer file transfer tool written in C++20 with Boost.Asio and OpenSSL. Every connection is TLS 1.3 with **mutual certificate authentication**, every file is **verified end to end with SHA-256**, and everything the receiver accepts from the network is validated before it is trusted.

This is also a security project, so besides how to use it, this README explains how it works, **what it defends against, and what it does not** (see [Threat model](#threat-model) and [Known limitations](#known-limitations)).

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Threat model](#threat-model)
- [Known limitations](#known-limitations)
- [Testing](#testing)
- [Project structure](#project-structure)
- [Roadmap](#roadmap)
- [License](#license)

## Features

- **Mutual TLS 1.3.** Only TLS 1.3 is accepted. Every connection is verified against a **trust list of certificate fingerprints**.
- **Per-peer trust.** No shared keys. You decide exactly which peers to trust by adding their unique fingerprint.
- **End-to-end integrity.** The sender hashes the file with SHA-256 and sends the hash in the header. The receiver hashes what it actually wrote and only keeps the file if the two match.
- **Disk protection.** Every upload reserves its space from one shared budget, so parallel uploads cannot fill the disk together, and 100 MiB is always left free.
- **Safe receiving.** Files are written to a temporary `.part` file and renamed only after verification. Existing files are never overwritten, and a failed transfer leaves nothing behind.
- **Strict input validation.** Header fields, file sizes and file names are checked against explicit rules before anything touches the disk.
- **Clear refusals.** If the receiver says no, it says why (untrusted peer, name not allowed, file too large, already exists, ...).
- **Timeouts and limits.** A peer gets 10 seconds to finish the TLS handshake, connections that go quiet for 30 seconds are closed, and the receiver accepts at most 64 connections at once.
- **P2P mode.** One process can receive and send at the same time, with an in-memory address book.
- **Progress bars** on both sides.

## Quick start

Tested on Ubuntu 24.04 (including WSL) with GCC 13 and Clang 18.

```bash
# 1. Dependencies (Debian/Ubuntu)
sudo apt install build-essential cmake libboost-dev libboost-system-dev libssl-dev

# 2. Get the code
git clone https://github.com/OmarAhmedTHE25th/P2P_Secure_File_Sharing.git
cd P2P_Secure_File_Sharing

# 3. Build
cmake -S . -B build
cmake --build build
cd build
```

### Identity and Trust

Before you can transfer files, you need an identity and you must exchange fingerprints with your peer.

1. **Generate your identity** (creates `identity.crt` and `identity.key`):
   ```bash
   ./P2P_Secure_File_Sharing identity generate "My Name"
   ```

2. **See your fingerprint**:
   ```bash
   ./P2P_Secure_File_Sharing identity fingerprint
   ```

3. **Trust a peer** (replace `<fp>` with their fingerprint):
   ```bash
   ./P2P_Secure_File_Sharing trust add <fp> "Friend Name"
   ```

### Try a transfer

In two terminals, from inside the `build` folder:

```bash
# terminal 1 (Receiver)
# First, trust yourself so you can test locally
./P2P_Secure_File_Sharing trust add $(./P2P_Secure_File_Sharing identity fingerprint) "me"
./P2P_Secure_File_Sharing receive 8080

# terminal 2 (Sender)
echo "hello" > test.txt
./P2P_Secure_File_Sharing send localhost 8080 test.txt
```

## Usage

```bash
# Identity management
P2P_Secure_File_Sharing identity generate <name>
P2P_Secure_File_Sharing identity fingerprint

# Trust management
P2P_Secure_File_Sharing trust add <fingerprint> <name>
P2P_Secure_File_Sharing trust remove <name_or_fingerprint>
P2P_Secure_File_Sharing trust list

# Transfer
P2P_Secure_File_Sharing receive <port> [save_folder]
P2P_Secure_File_Sharing send <host> <port> <file>
P2P_Secure_File_Sharing p2p <port> [save_folder]
```

## Threat model

### What is protected

- **Confidentiality and integrity of files in transit**, against anyone watching or tampering with the network.
- **Authentication**, ensuring you only talk to peers you have explicitly trusted.
- **The receiver's disk and file system**, against a malicious or buggy sender.
- **The receiver's availability**, against some (not all) resource-exhaustion tricks.

### Who the attacker is

1. **A network attacker** who can read, modify, drop or inject traffic, but does **not** have a trusted private key.
2. **An untrusted peer** who has their own identity but is not in your `trust.list`.
3. **A malicious trusted peer**, trying to exploit the protocol (limited by validation and disk budget).

### Threats and mitigations

| Threat | Mitigation | Checked by |
|--------|------------|------------|
| Eavesdropping | TLS 1.3 only | End-to-end test |
| Tampering | TLS integrity + SHA-256 file hash | Unit tests, E2E test |
| Impersonating a peer | Unique identities + Fingerprint verification | E2E trust test |
| A stranger connecting | **Handshake refused** if fingerprint not in trust list | E2E trust test |
| Path traversal | Strict filename rules (no separators, etc.) | Unit tests, fuzzer |
| Windows filename tricks | Explicit cross-platform rules | Unit tests, fuzzer |
| Overwriting files | Existing names and `.part` files refused | E2E test |
| Filling the disk | cap per file, shared disk budget, 100 MiB reserve | Unit tests |
| Malformed headers | Strict validation of types and lengths | Unit tests, fuzzer |
| Memory-safety bugs | ASan/UBSan in CI, fuzzed validation | CI |
| Idle/Silent connections | 10s handshake & 30s idle timeouts | E2E test |

## Known limitations

**Trust is manual.** You must out-of-band exchange fingerprints. There is no central authority or automatic discovery.

**"Shared Identity" Limitation (Legacy):** Previously, all peers shared one `server.crt`. We have moved to individual identities, but if you are still using a shared `identity.crt` among a group, remember that anyone in that group can impersonate anyone else *within* that group. Use unique identities for true security.

**Denial of service is only partly handled.**
- The 64-connection limit and the 10-second handshake timeout are global. A persistent attacker can still "squat" on all available slots.
- The disk budget only tracks this program's activity.

**File names.** Names are not checked for Unicode normalization. Names starting with `.` or longer than 200 bytes are refused.

## Testing

| What | How | What it covers |
|------|-----|----------------|
| **Unit tests** (48, GoogleTest) | `ctest --test-dir build` | Header layout, SHA-256 against known vectors (including file sizes right on the 64 KB chunk boundary), header validation limits, the file name rules, and the disk budget (parallel uploads, release on finish, free-space margin) |
| **End-to-end test** | `ctest --test-dir build` (Linux) | Starts a real receiver and sends real files over TLS: random 500 KB, 1 byte, empty, a name with a space. Checks byte-for-byte equality, that duplicates and `CON.txt` are refused and leave nothing behind, that connections beyond the limit are dropped, and that a silent peer is hung up on (this test takes about 12 seconds) |
| **Sanitizers** | `cmake -S . -B build-san -DCMAKE_BUILD_TYPE=Debug -DP2P_SANITIZE=ON`, then build and `ctest` | All of the above with AddressSanitizer and UndefinedBehaviorSanitizer; any memory error or undefined behavior fails the run |
| **Fuzzing** (libFuzzer) | see below | Header checks and file name sanitizer: random inputs are checked against rules that must hold for every input |

Run everything:

```bash
bash scripts/gen_certs.sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Fuzz for a minute (needs Clang):

```bash
sudo apt install clang libclang-rt-dev
cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ -DP2P_BUILD_TESTS=OFF -DP2P_BUILD_FUZZERS=ON
cmake --build build-fuzz --target fuzz_validation
mkdir -p corpus-work
./build-fuzz/fuzz_validation corpus-work fuzz/seeds -max_total_time=60
```

If the fuzzer finds an input that breaks a rule, it prints `PROPERTY VIOLATED: <rule>` and saves the input as `crash-<hash>`; replay it with `./build-fuzz/fuzz_validation crash-<hash>`.

Some security behavior is only **checked by hand so far**, not automated: a TLS 1.2 client is refused, a client with no certificate or with a different self-signed certificate is refused, a sender refuses a receiver whose certificate does not list the address it connected to, and a file sent with a wrong hash gets `HASH_MISMATCH` and leaves nothing on disk, and two simultaneous uploads onto a disk too small for both get one accepted and one refused. Turning these into automated tests is on the roadmap.

To make sure the fuzzer really can find bugs, I planted four on purpose one at a time (allowing `:` in names, dropping the length-match check, dropping the trailing-dot rule, dropping `CON` from the reserved list), and it caught each one within seconds. The fuzzer covers the validation logic only, not the network state machine.

GitHub Actions runs three jobs on every push: build and test (GCC and Clang), sanitizers, and a 60-second fuzz run.

## Project structure

```
main.cpp              Entry point, argument parsing, TLS context setup
p2p_node.hpp          Interactive P2P node: address book and commands
server_node.hpp       Accepts connections and performs the TLS handshake
server_session.hpp    Receiving state machine, one per incoming connection
client_node.hpp       Sending state machine, one per outgoing transfer
validation.hpp        Pure header checks and file name rules (unit tested, fuzzed)
protocol.hpp          Wire format and status codes
file_streaming.hpp    SHA-256 hashing and file size
tests/                Unit tests (GoogleTest)
fuzz/                 libFuzzer harness and seed inputs
scripts/gen_certs.sh  Generates a development certificate
scripts/e2e_test.sh   End-to-end transfer test
.github/workflows/    CI: build and test, sanitizers, fuzzing
```

## Roadmap

- Per-peer certificates with fingerprint pinning (trust on first use, like SSH `known_hosts`), replacing the single shared identity
- Per-address connection limits and rate limiting
- Automated tests for the security behavior that is currently checked by hand
- Persistent address book
- Resume interrupted transfers; send folders
- UTF-8 validation for file names, and testing on Windows
- A ThreadSanitizer pass over `p2p` mode, and Windows and macOS builds in CI

## License

MIT, see [LICENSE](LICENSE).
