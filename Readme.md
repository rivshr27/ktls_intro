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
##  Generate Certificate & Private Key

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
## Requirements to run ktls
1. Linux kernel 5.2 or newer.
2. Kernel must have CONFIG_TLS=y or CONFIG_TLS=m enabled.
3. Kernel must have CONFIG_TLS_DEVICE=y enabled.
4. OpenSSL must be built with -DOPENSSL_KTLS_SUPPORT.
5. Application must call SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS).
6. TLS protocol version must be TLS 1.2 only (kTLS does not support TLS 1.3 data offload).
7. Cipher suite must be AES-GCM (AES128-GCM-SHA256 or AES256-GCM-SHA384).
8. Socket must be a real TCP socket (no memory BIO, QUIC, pipes, or BIO pairs).
9. TLS handshake must complete successfully before enabling kTLS.
10. OpenSSL must perform setsockopt(TLS_TX/TLS_RX) automatically.
11. Kernel must accept the TLS_TX and TLS_RX setsockopt calls.
12. BIO_get_ktls_send() must return 1 to confirm TX kTLS activation.
13. BIO_get_ktls_recv() must return 1 to confirm RX kTLS activation.
14. /proc/net/tls_stat must exist on the system.
15. /proc/net/tls_stat counters must increase after sending >16KB data.
16. A certificate (cert.pem) and key (key.pem) must exist.
17. Application must use SSL_set_fd() to bind SSL to the TCP socket.
18. No CHACHA20 or CBC cipher must be used (unsupported by kTLS).
19. No TLS 1.3 handshake should occur (forces fallback to user-space TLS).
20. No BIO filter/wrapper layers should be used between OpenSSL and the socket.



| Counter                 | Meaning                                                                                         |
| ----------------------- | ----------------------------------------------------------------------------------------------- |
| **TlsCurrTxSw**         | Number of active (currently open) **TX kTLS sessions** using software encryption in the kernel. |
| **TlsCurrRxSw**         | Number of active (currently open) **RX kTLS sessions** using software decryption in the kernel. |
| **TlsCurrTxDevice**     | Number of active **transmit sessions offloaded to hardware** (TLS-offload NIC).                 |
| **TlsCurrRxDevice**     | Number of active **receive sessions offloaded to hardware** (TLS-offload NIC).                  |
| **TlsTxSw**             | Total number of **TLS records transmitted** using software kTLS since system boot.              |
| **TlsRxSw**             | Total number of **TLS records received** using software kTLS since system boot.                 |
| **TlsTxDevice**         | Total number of TLS records transmitted using **hardware TLS offload**.                         |
| **TlsRxDevice**         | Total number of TLS records received using **hardware TLS offload**.                            |
| **TlsDecryptError**     | Number of TLS records that failed decryption (authentication/tag failure).                      |
| **TlsRxDeviceResync**   | Number of times the kernel had to resynchronize with a TLS-offload NIC on RX.                   |
| **TlsDecryptRetry**     | Number of received TLS records the kernel needed to re-decrypt.                                 |
| **TlsRxNoPadViolation** | Padding-check related counter (mainly for CBC-mode TLS; mostly unused with AES-GCM).            |

## Useful Link:
1.http://gerryyang.com/linux%20performance/2025/05/25/kernel-tls-in-action.html
2.https://docs.kernel.org/networking/tls.html
---

