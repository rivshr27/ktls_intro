#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

void ssl_die(const char *msg) {
    std::cerr << msg << ": "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    exit(1);
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) ssl_die("SSL_CTX_new");

    // Enable kernel TLS
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(4433);
    inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr);

    if (connect(sock, (sockaddr*)&srv, sizeof(srv)) < 0) {
        perror("connect");
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Force TLS1.2 + AES128-GCM
    SSL_set_min_proto_version(ssl, TLS1_2_VERSION);
    SSL_set_max_proto_version(ssl, TLS1_2_VERSION);
    SSL_set_cipher_list(ssl, "ECDHE-RSA-AES128-GCM-SHA256");

    if (SSL_connect(ssl) <= 0) ssl_die("SSL_connect");

    std::cout << "[TLS] Connected successfully!\n";
    std::cout << "[TLS] Cipher: " << SSL_get_cipher(ssl) << "\n";

    long ktls_send = 0, ktls_recv = 0;
#if defined(BIO_get_ktls_send)
    ktls_send = BIO_get_ktls_send(SSL_get_wbio(ssl));
#endif
#if defined(BIO_get_ktls_recv)
    ktls_recv = BIO_get_ktls_recv(SSL_get_rbio(ssl));
#endif

    std::cout << "[kTLS] send=" << ktls_send
              << " recv=" << ktls_recv << "\n\n";

    std::cout << "========================================\n";
    std::cout << "Interactive Chat Mode - Type messages\n";
    std::cout << "Press Ctrl+C to quit\n";
    std::cout << "========================================\n\n";

    // Interactive loop
    std::string line;
    while (true) {
        std::cout << "You: ";
        std::getline(std::cin, line);

        if (line.empty()) continue;

        // Send message
        int sent = SSL_write(ssl, line.c_str(), line.length());
        if (sent <= 0) {
            std::cerr << "Failed to send message\n";
            break;
        }

        // Receive response
        char buf[4096];
        int n = SSL_read(ssl, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = 0;
            std::cout << "Server: " << buf << "\n\n";
        } else {
            std::cerr << "Connection closed by server\n";
            break;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    std::cout << "\nDisconnected.\n";
    return 0;
}
