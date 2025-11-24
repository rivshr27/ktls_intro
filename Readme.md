# kTLS Server & Client Demo (OpenSSL + Kernel TLS)

This repository contains a minimal C++ example demonstrating how to use **Kernel TLS (kTLS)** with **OpenSSL** on Linux.

The server:

- Performs a TLS 1.2 handshake using AES128-GCM
- Enables kTLS in both directions (TX + RX)
- Prints `/proc/net/tls_stat` to show kernel TLS activity
- Echoes messages back to the client

The client simply connects, sends messages, and receives echo replies.

---
## 📁 Project Structure

```
ktls_server.cpp   # Server with kTLS enabled
ktls_client.cpp   # Simple TLS client
README.md
cert.pem           # TLS certificate
key.pem            # TLS key
```

---

## 🔐 Generate Certificate & Private Key

Generate a self-signed certificate (valid 365 days):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout key.pem \
    -out cert.pem \
    -subj "/CN=localhost"
```

---

## Build Instructions

### Build the server:

```bash
g++ ktls_server.cpp -o ktls_server -lssl -lcrypto
```

### Build the client:

```bash
g++ ktls_client.cpp -o ktls_client -lssl -lcrypto -std=c++17
```

---

##  Run the Server

```bash
./ktls_server cert.pem key.pem
```

You should see output like:

```
Server listening on 0.0.0.0:4433
[TLS] Handshake complete. Cipher: ECDHE-RSA-AES128-GCM-SHA256
[kTLS] send=1 recv=1
```

And `/proc/net/tls_stat` will show increasing counters:

```
TlsTxSw: 25 → 27
TlsRxSw: 25→ 27
```

---

## Run the Client

Compile:

```bash
g++ -o ktls_client ktls_client.cpp -lssl -lcrypto -std=c++17
```

Run:

```bash
./ktls_client
```

Now type messages — the server will echo them back and print updated TLS stats.

---

## Checking kTLS Stats

The server automatically prints `/proc/net/tls_stat`, but you can also check manually:

```bash
cat /proc/net/tls_stat
```

Example:

```
TlsCurrTxSw      2
TlsCurrRxSw      2
TlsTxSw         27
TlsRxSw         27
...
```

This confirms the kernel is encrypting/decrypting TLS records.

---

##  Notes

* kTLS requires **TLS 1.2 + AES-GCM**. TLS 1.3 is not fully supported for data-plane offload.
* Small messages do **not** increment counters because they are buffered inside TLS records.
* Once a message exceeds **16KB**, new TLS records are created and counters increase.

---

## Test Large Data (forces TLS records)

```bash
head -c 20000 /dev/zero | openssl s_client -connect 127.0.0.1:4433 -quiet
```

---

