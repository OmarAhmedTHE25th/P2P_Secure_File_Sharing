### User Guide: New Features in Secure File Sharing

Welcome! We've added several new features to make your file sharing experience safer, faster, and easier to use. Here is a simple breakdown of what’s new:

#### 1. Digital Handshakes (Mutual Security)
Previously, only your computer checked if the server was safe. Now, it’s a two-way street!
- **What it means:** Both the sender and the receiver must "show their ID" (digital certificates) before any file is sent.
- **Why it matters:** This prevents strangers or impostors from connecting to your computer. It ensures you are only talking to people you trust.
- **Peer Fingerprints:** When someone connects, you'll see a unique "fingerprint" (a string of letters and numbers). You can use this to verify exactly who is on the other end.

#### 2. Automatic Disconnects (Timeouts)
Have you ever had a connection just hang there doing nothing? Not anymore.
- **What it means:** If a connection goes silent for more than 30 seconds, the app will automatically close it.
- **Why it matters:** This keeps your computer's resources free and prevents "silent" users from hogging your connection.

#### 3. Two-Way Sharing (P2P Mode)
You no longer have to choose between only sending or only receiving.
- **What it means:** You can now run the app in `p2p` mode. This allows you to listen for incoming files while you are busy sending files to others at the same time.
- **How to use it:** Just start the app with the `p2p` command followed by your port number.

#### 4. Your Personal Address Book
Tired of typing in long IP addresses every time you want to send a file?
- **What it means:** You can now save your friends' connection details with a simple name.
- **How to use it:** Use the `add` command to save a name (e.g., `add alice 192.168.1.5 8080`). Then, you can just use `send_to alice my_photo.jpg` to send files instantly.

#### 5. Real-Time Progress Bars
No more guessing if a file is actually moving or how long it will take.
- **What it means:** As a file is being sent or received, you will see a visual bar `[=====     ] 50%` showing you exactly how much progress has been made.
- **Why it matters:** You get instant feedback that the transfer is working and can see exactly when it’s about to finish.

---
**Summary of New Commands in P2P Mode:**
- `add <name> <ip> <port>`: Save a friend to your address book.
- `send_to <name> <file>`: Send a file to a saved friend.
- `send <ip> <port> <file>`: Send a file to a one-time address.
- `exit`: Safely close the program.
