# P2P Secure File Sharing

A secure, peer-to-peer file sharing application built with C++ using Boost.Asio and OpenSSL. This application supports encrypted file transfers with mutual authentication (mTLS), progress tracking, and an interactive P2P mode.

## Features

- **Digital Handshakes (Mutual TLS):** Both parties must provide valid certificates. Prevents unauthorized connections.
- **Automatic Disconnects:** Connections are closed if silent for more than 30 seconds to free up resources.
- **P2P Mode:** Listen for incoming files while simultaneously sending files to others.
- **Address Book:** Save peer details with aliases for quick access.
- **Real-Time Progress Bars:** Visual feedback during file transfers.

## Tech Stack

- **Language:** C++20
- **Framework:** Boost.Asio (for networking)
- **Security:** OpenSSL (TLS 1.3)
- **Build System:** CMake (>= 3.28)

## Requirements

- C++20 compatible compiler (e.g., GCC 10+, Clang 10+, MSVC 19.29+)
- CMake (>= 3.28)
- Boost Libraries (specifically `system` and `asio`)
- OpenSSL Development headers and libraries
- (TODO: List any specific OS dependencies if found)

## Setup & Build

1. **Clone the repository:**
   ```bash
   git clone https://github.com/OmarAhmedTHE25th/P2P_Secure_File_Sharing.git
   cd P2P_Secure_File_Sharing
   ```

2. **Generate Certificates:**
   The application requires `server.crt` and `server.key` in the execution directory.
   ```bash
   # Example self-signed cert generation (for development)
   openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
   ```

3. **Build using CMake:**
   ```bash
   mkdir build
   cd build
   cmake ..
   cmake --build .
   ```

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


## Project Structure

- `main.cpp`: Entry point and mode handling.
- `p2p_node.hpp`: Logic for the interactive P2P node.
- `server_node.hpp` / `server_session.hpp`: Server-side connection handling.
- `client_node.hpp`: Client-side connection handling.
- `protocol.hpp`: Communication protocol definitions.
- `file_streaming.hpp`: Utilities for file I/O and streaming.
- `CMakeLists.txt`: Build configuration.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
