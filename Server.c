#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF 1024

void ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    // SSL_get_verify_result()This is the point. SSL_CTX_set_verify()Only when the configuration is enabled or not and the authentication is not executed, can the function be called to verify the authentication
    // If the verification fails, the program throws an exception to terminate the connection
    if(SSL_get_verify_result(ssl) == X509_V_OK){
        printf("Certificate verification passed\n");
    }
    if (cert != NULL) {
        printf("Digital certificate information:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("certificate: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    } else
        printf("No certificate information!\n");
}

void ServerConfigCTX(SSL_CTX *ctx) {
    // Two way validation
    // SSL_VERIFY_PEER---Certificate certification is required and will be released without certificate
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT---The client is required to provide a certificate, but it will be released if no certificate is used alone
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    // Set trust root certificate
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt",NULL)<=0){
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* Loads the user's digital certificate, which is used to send to the client. Certificate contains public key */
    const char* serverCrt = "server.crt";
    if (SSL_CTX_use_certificate_file(ctx, serverCrt, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* Load user private key */
    const char* privateKey = "server_rsa_private.pem.unsecure";
    if (SSL_CTX_use_PrivateKey_file(ctx, privateKey, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* Check whether the user's private key is correct */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
}

int main(int argc, char **argv) {
    int sockfd, new_fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    unsigned int myport, lisnum;
    char buf[MAXBUF + 1];
    SSL_CTX *ctx;

    if (argv[1])
        myport = atoi(argv[1]);
    else
        myport = 7838;

    if (argv[2])
        lisnum = atoi(argv[2]);
    else
        lisnum = 2;

    /* SSL Library initialization */
    SSL_library_init();
    /* Load all SSL algorithms */
    OpenSSL_add_all_algorithms();
    /* Load all SSL error messages */
    SSL_load_error_strings();
    /* Generate an SSL? CTX in a SSL V2 and V3 standard compatible way, that is, SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_server_method());
    /* You can also use sslv2? Server? Method() or SSLv3? Server? Method() to represent V2 or V3 standards separately */
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    ServerConfigCTX(ctx);

    /* Turn on a socket monitor */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    } else
        printf("socket created\n");

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(myport);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))
            == -1) {
        perror("bind");
        exit(1);
    } else
        printf("binded\n");

    if (listen(sockfd, lisnum) == -1) {
        perror("listen");
        exit(1);
    } else
        printf("begin listen\n");

    while (1) {
        SSL *ssl;
        len = sizeof(struct sockaddr);
        /* Wait for the client to connect */
        if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len))
                == -1) {
            perror("accept");
            exit(errno);
        } else
            printf("server: got connection from %s, port %d, socket %d\n",
                    inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port),
                    new_fd);

        /* A new SSL based on ctx */
        ssl = SSL_new(ctx);
        /* Add the socket of the connected user to SSL */
        SSL_set_fd(ssl, new_fd);
        /* Establish SSL connection */
        if (SSL_accept(ssl) == -1) {
            perror("accept");
            close(new_fd);
            break;
        }
        ShowCerts(ssl);

        /* Start processing data transfer on each new connection */
        bzero(buf, MAXBUF + 1);
        strcpy(buf, "server->client");
        /* Send message to client */
        len = SSL_write(ssl, buf, strlen(buf));

        if (len <= 0) {
            printf("news'%s'Sending failed! The error code is%d，The error message is'%s'\n", buf, errno,
                    strerror(errno));
            goto finish;
        } else
            printf("news'%s'Sent successfully, sent in total%d Byte!\n", buf, len);

        bzero(buf, MAXBUF + 1);
        /* Receive messages from clients */
        len = SSL_read(ssl, buf, MAXBUF);
        if (len > 0)
            printf("Message received successfully:'%s'，common%d Bytes of data\n", buf, len);
        else
            printf("Message reception failed! The error code is%d，The error message is'%s'\n",
            errno, strerror(errno));
        /* Processing the end of data receiving and sending on each new connection */
        finish:
        /* Close SSL connection */
        SSL_shutdown(ssl);
        /* Release SSL */
        SSL_free(ssl);
        /* Close socket */
        close(new_fd);
    }
    /* Turn off listening socket */
    close(sockfd);
    /* Release CTX */
    SSL_CTX_free(ctx);
    return 0;
}
