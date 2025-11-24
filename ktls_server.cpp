#include <iostream>
#include <fstream>
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

void print_tls_stat() {
    std::ifstream f("/proc/net/tls_stat");
    if (!f.good()) {
        std::cout << "/proc/net/tls_stat missing (kernel may not support kTLS)\n";
        return;
    }

    std::cout << "=== /proc/net/tls_stat ===\n";
    std::string line;
    while (std::getline(f, line)) std::cout << line << "\n";
    std::cout << "==========================\n";
}

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " cert.pem key.pem\n";
        return 1;
    }

    const char *certfile = argv[1];
    const char *keyfile  = argv[2];

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) ssl_die("SSL_CTX_new");

    // Enable kernel TLS
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);

    if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) <= 0)
        ssl_die("load cert");

    if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) <= 0)
        ssl_die("load key");

    if (!SSL_CTX_check_private_key(ctx))
        ssl_die("key mismatch");

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(listen_fd, (sockaddr*)&addr, sizeof(addr));
    listen(listen_fd, 5);

    std::cout << "Server listening on 0.0.0.0:4433\n";
    print_tls_stat();

    while (true) {
        sockaddr_in cli{};
        socklen_t sz = sizeof(cli);
        int cfd = accept(listen_fd, (sockaddr*)&cli, &sz);

        std::cout << "\n[NEW CONNECTION]\n";

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, cfd);

        // Force TLS1.2 + AES128-GCM
        SSL_set_min_proto_version(ssl, TLS1_2_VERSION);
        SSL_set_max_proto_version(ssl, TLS1_2_VERSION);
        SSL_set_cipher_list(ssl, "ECDHE-RSA-AES128-GCM-SHA256");

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(cfd);
            continue;
        }

        std::cout << "[TLS] Handshake complete. Cipher: "
                  << SSL_get_cipher(ssl) << "\n";

        BIO *wbio = SSL_get_wbio(ssl);
        BIO *rbio = SSL_get_rbio(ssl);

        long ktls_send = 0, ktls_recv = 0;

#if defined(BIO_get_ktls_send)
        ktls_send = BIO_get_ktls_send(wbio);
#endif
#if defined(BIO_get_ktls_recv)
        ktls_recv = BIO_get_ktls_recv(rbio);
#endif

        std::cout << "[kTLS] send=" << ktls_send
                  << " recv=" << ktls_recv << "\n\n";

        print_tls_stat();

        // Interactive echo loop
        std::cout << "Ready for messages (client will type)...\n\n";

        while (true) {
            char buf[1024];
            int n = SSL_read(ssl, buf, sizeof(buf)-1);

            if (n <= 0) {
                std::cout << "\n[Client disconnected]\n";
                break;
            }

            buf[n] = 0;
            std::cout << "Client says: " << buf << "\n";

            // Echo back with prefix
            std::string response = "Echo: " + std::string(buf);
            SSL_write(ssl, response.c_str(), response.length());

            // Print stats after each exchange
            std::cout << "Stats after this message:\n";
            print_tls_stat();
            std::cout << "\n";
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}
