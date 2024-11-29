#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstdlib>
#include <main.h>
#include <string>
#include <unordered_map>

const int PORT = 3001;
const int BUFFER_SIZE = 1024;

SSL_CTX *create_context(){
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "/etc/letsencrypt/live/eryilmazvinc.tr/fullchain.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "/etc/letsencrypt/live/eryilmazvinc.tr/privkey.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // NULL = verify_callback

    const char *session_id_context = "unique_session_id";
    if (SSL_CTX_set_session_id_context(ctx, (const unsigned char *)session_id_context, strlen(session_id_context)) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

std::string getContentType(const std::string& path) {
    std::cout << path << "\r\n";

    return "application/octect-stream";
};

int main_server() {
    int sock, new_sock;
    struct sockaddr_in addr;
    int opt = 1;
    int addrlen = sizeof(addr);
    char buffer[BUFFER_SIZE] = {0};

    OPENSSL_init_ssl(0, NULL); // 0 = default settings // NULL = i don't want
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
       perror("socket failed");
       exit(EXIT_FAILURE);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
       perror("setsockopt");
       exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET; // IPv4
    addr.sin_addr.s_addr = INADDR_ANY; // 0.0.0.0
    addr.sin_port = htons(PORT);

    if (bind(sock, (struct sockaddr *)&addr, addrlen) < 0) {
       perror("bind failed");
       exit(EXIT_FAILURE);
    }

    if(listen(sock, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    std::cout << "Listening on port: " << PORT << "\n";

    while (true) {
        if ((new_sock = accept(sock, (struct sockaddr *)&addr, (socklen_t *)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(new_sock);
            continue;
        }

        int bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';

            std::string filepath = "src/main/page/index.html";
            std::ifstream file(filepath);
            if (!file.is_open()) {
                std::cerr << "Failed to open " << filepath << "\r";
            }

            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string content = buffer.str();

            std::string response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: " + getContentType(filepath) + "\r\n";
            response += "Content-Length: " + std::to_string(content.size()) + "\r\n";
            response += "\r\n";

            SSL_write(ssl, response.c_str(), response.size());
            SSL_write(ssl, content.c_str(), content.size());

            file.close();
        } else {
            ERR_print_errors_fp(stderr); 
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(new_sock);
    }

    return 0;
}
