### Project Overview: P2P Secure File Sharing

This project is a private, peer-to-peer way for two computers to send files to
each other over a network. Imagine a digital courier service where every
package travels through an encrypted tunnel, and both the sender and receiver
must show their digital IDs before the exchange can begin.

The project is written in C++20. Boost.Asio provides the asynchronous network
plumbing, OpenSSL provides TLS 1.3 and SHA-256, and Qt 6 provides the optional
desktop interface.

---

### The Main Ideas

1. **Every node has an identity.** A certificate and private key identify a
   computer to its peers.
2. **Trust is explicit.** A peer is accepted only when its certificate
   fingerprint is in the local trust list.
3. **Every transfer is verified.** The receiver hashes the bytes it writes and
   keeps the file only when the hash matches the sender's hash.
4. **The receiver is defensive.** It validates names, sizes, headers, disk
   space, timeouts, and connection counts before accepting data.
5. **The network is asynchronous.** A server can accept multiple senders while
   each transfer progresses independently.

This is not a central server. Both computers run the same program, and either
one can listen, send, or do both at the same time.

---

### Ways to Use the Project

#### Command-line application

The executable supports three transfer modes and several identity commands:

```text
P2P_Secure_File_Sharing receive <port> [save_folder]
P2P_Secure_File_Sharing send <host> <port> <file>
P2P_Secure_File_Sharing p2p <port> [save_folder]

P2P_Secure_File_Sharing init [--force] [name]
P2P_Secure_File_Sharing fingerprint
P2P_Secure_File_Sharing trust add <fingerprint> <name>
P2P_Secure_File_Sharing trust list
P2P_Secure_File_Sharing trust remove <name|fingerprint>
```

- **`init`** creates `identity.crt` and `identity.key`, then prints the
  certificate fingerprint. The private key may be protected with a passphrase.
- **`fingerprint`** prints the local identity fingerprint again.
- **`trust add`** adds another node's fingerprint to
  `trusted_peers.txt`.
- **`trust list`** displays the trusted aliases and fingerprints.
- **`trust remove`** immediately removes a peer from the local trust list.
- **`receive`** listens for incoming files and saves them to `received` unless
  another folder is supplied.
- **`send`** sends one file and exits with success only when the receiver
  confirms that the file was verified and saved.
- **`p2p`** listens for incoming files and also opens a small command prompt for
  outgoing transfers.

The `p2p` command prompt supports:

```text
add <name> <host> <port>
send_to <name> <file>
send <host> <port> "<file>"
exit
```

The P2P address book is separate from the trust list. It remembers where a
peer is reachable, but it does not decide whether that peer is trusted. The
address book exists only in memory and is lost when the process exits.

#### Qt desktop application

When built with `P2P_BUILD_GUI=ON`, the project also provides a Qt 6 desktop
application with three tabs:

- **Send File** selects a file, destination host, and port. It displays the
  percentage, transferred megabytes, authenticated peer, and activity log.
- **Receive Files** starts the listener, chooses the port and save directory,
  and displays the incoming transfer progress and amount received.
- **Trusted Peers** adds and removes trusted aliases and certificate
  fingerprints.

The GUI creates or unlocks its identity with a passphrase dialog. Its identity
and trust files are stored under Qt's application-data directory through
`QStandardPaths::AppDataLocation`, rather than the command-line process's
current directory.

---

### How Each Part Works

#### 1. The Gateway: `main.cpp`

This is the command-line entry point. It parses the mode and arguments,
checks that an identity exists, loads the trust store, configures the correct
TLS context, and starts the requested node.

It also validates ports and returns a useful exit status. In `send` mode, a
non-zero exit status means the receiver did not confirm a successful transfer.

#### 2. Digital Identities: `identity.hpp` and `cli_identity.hpp`

`identity.hpp` creates the certificate and private key and calculates the
certificate's SHA-256 fingerprint. The private key stays local and should
never be shared or committed.

`cli_identity.hpp` provides the `init`, `fingerprint`, and `trust` commands,
including hidden password entry on interactive terminals. The certificate is
the public identity; the private key proves that the node really owns it.

#### 3. The Address Book: `trust_store.hpp`

The trust store is the local guest list. It maps a fingerprint to a friendly
name and stores one peer per line in `trusted_peers.txt`.

The list is read when a connection is checked, so adding or removing a peer
takes effect without restarting the server. A trusted name is only a label;
the fingerprint is the value that actually grants access.

#### 4. TLS Trust: `tls_trust.hpp`

This file configures OpenSSL for mutual TLS 1.3:

- The server presents its certificate to the client.
- The client presents its certificate to the server.
- Both sides verify the peer certificate.
- The certificate fingerprint is compared against the local trust store.

This prevents a network observer or impostor from silently replacing a trusted
peer. Encryption protects the traffic, while the fingerprint check answers
the separate question, “Which node is on the other end?”

#### 5. The Waiting Receiver: `server_node.hpp`

`ServerNode` owns the listening TCP acceptor. It accepts a connection, starts a
10-second TLS handshake timer, and rejects connections when the 64-connection
limit has been reached.

After a successful handshake, it creates one `ServerSession` for that
connection and immediately returns to accepting the next one. A
`ConnectionSlot` keeps a connection counted from the handshake through the
end of the session, even when the connection fails early.

The server also owns one shared `DiskBudget`, so simultaneous uploads reserve
space from the same accounting pool.

#### 6. One Incoming Transfer: `server_session.hpp`

`ServerSession` is the state machine for one received file. It:

1. Reads and validates the metadata header.
2. Validates the filename and checks the file-size limit.
3. Refuses names that could escape the save directory or behave differently
   across operating systems.
4. Checks for existing destination files and reserves disk space.
5. Sends `READY` before the sender is allowed to stream bytes.
6. Writes incoming bytes to a temporary `.part` file.
7. Updates SHA-256 while writing.
8. Reports progress when the integer percentage changes, rather than once per
   64 KiB chunk.
9. Reads the end-of-file marker and compares the calculated hash with the
   sender's hash.
10. Renames the temporary file to its final name only after verification.

If anything fails, the temporary file is removed and the receiver sends a
specific refusal or failure status where possible. A 30-second idle timer
closes a session that stops making progress.

#### 7. The Active Sender: `client_node.hpp`

`ClientNode` resolves the destination, connects to it, performs the TLS 1.3
handshake, and sends the file in asynchronous steps:

1. Send metadata and the filename.
2. Wait for the receiver's `READY` acknowledgement.
3. Stream the file in `FileStreamer::CHUNK_SIZE` pieces.
4. Send `END_OF_FILE`.
5. Wait for the final acknowledgement.

It reports transfer progress, peer authentication, and completion through
`TransferEvents`. The sender only reports success after the receiver confirms
the file was verified and saved.

#### 8. The GUI Bridge: `gui/network_bridge.hpp` and `.cpp`

The GUI cannot block its interface thread on network operations. `NetworkBridge`
owns the Boost.Asio context and runs it on a worker thread. It translates
network callbacks into Qt signals:

- `transferProgress` and `transferCompleted` for outgoing transfers.
- `receiveProgress` and `receiveFinished` for incoming transfers.
- `peerAuthenticated` for the verified peer identity.
- `serverStatus` and `logMessage` for status and diagnostics.

The bridge passes the same `TransferEvents` callbacks into `ClientNode` and
`ServerNode`, keeping the networking code independent of Qt.

#### 9. The GUI Window: `gui/main_window.hpp` and `.cpp`

`MainWindow` builds the three tabs, handles buttons and dialogs, and connects
the bridge signals to the visible controls. The receive progress bar displays
both percentage and received/total megabytes. It reaches 100% on success and
resets on a failed transfer.

#### 10. The Rules of Exchange: `protocol.hpp`

The wire protocol uses a packed, fixed-size 47-byte header. All multi-byte
numbers are stored in big-endian order:

| Offset | Size | Field | Meaning |
|-------:|-----:|-------|---------|
| 0 | 1 | `msg_type` | Metadata, chunk, end-of-file, or ACK |
| 1 | 4 | `payload_len` | Number of bytes following the header |
| 5 | 8 | `total_file_size` | Total file size |
| 13 | 2 | `filename_len` | Filename length |
| 15 | 32 | `file_hash` | SHA-256 of the complete file |

The important acknowledgement statuses are:

- `READY`: metadata was accepted and bytes may be sent.
- `OK`: the hash matched and the file was saved.
- `HASH_MISMATCH`: the received content was discarded.
- `BAD_REQUEST`: the header or request was malformed.
- `FILE_TOO_LARGE`, `UNSAFE_FILENAME`, `ALREADY_EXISTS`, and `NO_SPACE`:
  specific reasons the receiver refused the transfer.

#### 11. The Safety Inspector: `validation.hpp`

This is deliberately independent of sockets and disk access, which makes it
easy to unit test and fuzz.

- Filenames must be 1 to 200 bytes.
- Path separators, drive-colon syntax, control characters, wildcards, and
  Windows-reserved device names are rejected.
- Hidden names and names ending in a dot or space are rejected.
- A metadata filename length must match its payload length.
- Files larger than 10 GiB are rejected by default.

The same explicit rules are used on every operating system rather than relying
on whichever filesystem happens to be underneath the receiver.

#### 12. Disk Protection: `disk_budget.hpp`

Before receiving a file, the server reserves its full expected size from a
shared, mutex-protected budget. A reservation is released automatically when
the transfer ends, fails, or disconnects. As bytes are written, those bytes
stop counting as “still promised.”

The default policy keeps at least 100 MiB free. This prevents several
simultaneous uploads from each seeing enough space individually and then
filling the disk together.

#### 13. File Hashing and Streaming: `file_streaming.hpp`

This helper reads and hashes files without loading an entire file into memory.
The sender calculates the SHA-256 before or while streaming, and the receiver
calculates it over the bytes actually written. The final comparison catches
corruption or an unexpected file body.

---

### The Complete Workflow

1. **Create identities.** Each computer generates its own certificate and
   private key.
2. **Exchange fingerprints safely.** Each person gives the other their
   fingerprint through a channel they already trust.
3. **Build the guest lists.** Each computer adds the other fingerprint with
   `trust add`.
4. **Start a listener.** The receiver starts `receive` or the GUI listener.
5. **Connect securely.** The sender connects and both sides complete mutual
   TLS 1.3 verification.
6. **Check metadata.** The receiver validates the name, size, destination, and
   available disk budget.
7. **Wait for permission.** The receiver sends `READY`; no file bytes are
   streamed before this point.
8. **Transfer safely.** The sender streams chunks while the receiver writes to
   a temporary file and hashes them.
9. **Verify and publish.** A matching SHA-256 hash causes the `.part` file to
   be renamed. A mismatch or error causes it to be discarded.
10. **Report the result.** The sender and GUI receive the final success or
    failure status.

---

### Building the Project

The core application uses CMake, C++20, Boost.System, and OpenSSL:

```bash
sudo apt install build-essential cmake libboost-dev libboost-system-dev libssl-dev
cmake -S . -B build
cmake --build build
```

To build the Qt application:

```bash
sudo apt install qt6-base-dev
cmake -S . -B build-gui -DP2P_BUILD_GUI=ON -DP2P_BUILD_TESTS=OFF
cmake --build build-gui --target P2P_Secure_File_Sharing_GUI
```

The project can also build the fuzz target with Clang:

```bash
cmake -S . -B build-fuzz -DP2P_BUILD_TESTS=OFF -DP2P_BUILD_FUZZERS=ON \
  -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz --target fuzz_validation
```

---

### Testing and Automation

The project includes GoogleTest unit tests for:

- Packet layout and byte order.
- SHA-256 hashing and file-size boundaries.
- Header and filename validation.
- Disk-budget reservations and releases.
- Identity and trust-store behavior.
- TLS trust decisions.

The end-to-end trust test creates two temporary identities, checks rejection
before trust, checks a successful transfer after trust, and checks that
removing trust takes effect without restarting the server.

Run the tests with:

```bash
ctest --test-dir build --output-on-failure
```

GitHub Actions builds with GCC and Clang, runs the unit and end-to-end tests,
and runs a separate AddressSanitizer/UndefinedBehaviorSanitizer build. A
Clang libFuzzer job feeds random input to the header and filename validation
code.

---

### What the Project Protects

- **Files in transit:** TLS 1.3 encrypts traffic and detects tampering.
- **Peer identity:** mutual certificates and local fingerprint trust prevent
  unknown peers and common man-in-the-middle substitutions.
- **File integrity:** SHA-256 is checked before a received file becomes real.
- **The filesystem:** safe names, temporary files, no-overwrite behavior, and
  size limits reduce damage from malicious senders.
- **Disk availability:** concurrent transfers share a reservation budget and
  leave a free-space margin.
- **Basic connection exhaustion:** handshake and idle timeouts plus a
  64-connection server limit prevent some simple resource attacks.

### What It Does Not Protect

- It does not scan file contents for malware.
- It does not hide the fact that two peers are communicating or hide their IP
  addresses.
- It cannot protect a private key that has been stolen or a computer that is
  already compromised.
- Trust is only as good as the fingerprint that was verified before it was
  added.
- There is no resume for interrupted transfers, folder transfer, per-address
  rate limit, or persistent P2P address book.
- The disk budget tracks this program's uploads; another application can still
  consume the physical disk space.
- Native Windows and macOS builds are not covered by the current CI setup.

---

### Summary for a Non-Technical Person

Think of this project as a **private club with a secure delivery room**:

- Your **membership card** is your certificate and private key
  (`identity.hpp`).
- Your **guest list** is `trusted_peers.txt`
  (`trust_store.hpp`).
- The **encrypted entrance** is mutual TLS 1.3 (`tls_trust.hpp`).
- The **front desk** is `ServerNode`.
- The **delivery room** for one incoming package is `ServerSession`.
- The **delivery truck** is `ClientNode`.
- The **standard form** describing each package is `protocol.hpp`.
- The **safety inspector** is `validation.hpp`.
- The **space accountant** is `disk_budget.hpp`.
- The **tamper seal** is the SHA-256 hash.
- The **desktop receptionist** is the Qt GUI and `NetworkBridge`.

Only a peer on the guest list can enter, only a safe package can be accepted,
and the package is not placed on the shelf until its tamper seal matches.
