# P2P Secure File Sharing

A secure, peer-to-peer file sharing application built with C++20 using Boost.Asio and OpenSSL. This application supports encrypted file transfers with mutual authentication (mTLS), progress tracking, and an interactive P2P mode.

## Features

- **Digital Handshakes (Mutual TLS):** Both parties must provide valid certificates. Prevents unauthorized connections.
- **Automatic Disconnects:** Connections are closed if silent for more than 30 seconds to free up resources.
- **P2P Mode:** Listen for incoming files while simultaneously sending files to others.
- **Address Book:** Save peer details with aliases for quick access in interactive mode.
- **Real-Time Progress Bars:** Visual feedback during file transfers.
- **SHA-256 Verification:** (TODO: Verify if hashing is used for integrity check during/after transfer).

## Tech Stack

- **Language:** C++20
- **Networking:** [Boost.Asio](https://www.boost.org/doc/libs/release/libs/asio/)
- **Security:** [OpenSSL](https://www.openssl.org/) (TLS 1.3, Mutual Auth)
- **Build System:** CMake (>= 3.28)
- **Unit Testing:** [GoogleTest](https://github.com/google/googletest)

## Requirements

- **Compiler:** C++20 compatible compiler (GCC 10+, Clang 10+, MSVC 19.29+)
- **CMake:** Version 3.28 or higher
- **Boost Libraries:** `system` and `asio` components
- **OpenSSL:** Development headers and libraries
- **Operating System:** Cross-platform (Windows, Linux, macOS), though E2E scripts require a Bash-like environment (WSL/Linux).

## Setup & Build

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/OmarAhmedTHE25th/P2P_Secure_File_Sharing.git
    cd P2P_Secure_File_Sharing
    ```

2.  **Generate Certificates:**
    The application requires `server.crt` and `server.key` in the execution directory for mTLS.
    You can use the provided script (Linux/WSL):
    ```bash
    bash scripts/gen_certs.sh
    ```
    Or manually:
    ```bash
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
    ```

3.  **Build using CMake:**
    ```bash
    mkdir build && cd build
    cmake ..
    cmake --build .
    ```
    Note: Certificates are automatically copied to the build directory if they exist in the project root during the CMake configuration step.

## Usage

The application can be run in three modes: `receive`, `send`, or `p2p`.

### 1. Receive Mode
Listen for incoming file transfers.
```bash
./P2P_Secure_File_Sharing receive <port> [save_folder]
```
- `<port>`: Port to listen on.
- `[save_folder]`: (Optional) Directory to save received files. Defaults to `received`.

### 2. Send Mode
Send a file to a specific address once.
```bash
./P2P_Secure_File_Sharing send <host> <port> <file>
```

### 3. P2P Mode (Interactive)
Run as a node that can both receive and send files.
```bash
./P2P_Secure_File_Sharing p2p <port> [save_folder]
```

**Interactive Commands in P2P Mode:**
- `add <name> <host> <port>`: Save a friend to your address book.
- `send_to <name> <file>`: Send a file to a saved friend.
- `send <host> <port> <file>`: Send a file to a one-time address.
- `exit`: Safely close the program.

## Scripts

- `scripts/gen_certs.sh`: Generates self-signed certificates for development.
- `scripts/e2e_test.sh`: Performs a full end-to-end transfer test (requires `timeout` and `bash`).

## Environment Variables

- (TODO: No custom environment variables currently detected. The application relies on command-line arguments and local certificate files.)

## Tests

### Unit Tests
Built by default if `P2P_BUILD_TESTS` is `ON` (default).
```bash
cd build
ctest --output-on-failure -R unit_tests
# Or run the executable directly:
./bin/unit_tests
```

### End-to-End Test
On Linux/WSL, an E2E test is registered with CTest:
```bash
ctest -R end_to_end
```

## Project Structure

- `main.cpp`: Application entry point and mode dispatcher.
- `p2p_node.hpp`: Interactive P2P node logic and command loop.
- `server_node.hpp` / `server_session.hpp`: TLS server implementation and session management.
- `client_node.hpp`: TLS client implementation for file sending.
- `protocol.hpp`: Data structures and constants for the communication protocol.
- `file_streaming.hpp`: Utilities for chunked file I/O.
- `validation.hpp`: Input validation utilities.
- `tests/`: GTest-based unit tests.
- `scripts/`: Helper scripts for development and testing.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
