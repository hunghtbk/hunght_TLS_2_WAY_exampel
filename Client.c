#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
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

void ClientConfigCTX(SSL_CTX *ctx) {

    // Two way validation
    // SSL_VERIFY_PEER---Certificate certification is required and will be released without certificate
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT---The client is required to provide a certificate, but it will be released if no certificate is used alone
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    // Set trust root certificate
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt",NULL)<=0){
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* Loads the user's digital certificate, which is used to send to the server. Certificate contains public key */
    const char* clientCrt = "client.crt";
    if (SSL_CTX_use_certificate_file(ctx, clientCrt, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* Load user private key */
    const char* privateKey = "client_rsa_private.pem.unsecure";
    if (SSL_CTX_use_PrivateKey_file(ctx, privateKey, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* Check if the user's private key is correct */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    int sockfd, len;
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];
    SSL_CTX *ctx;
    SSL *ssl;

    /* SSL For library initialization, refer to ssl-server.c code */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create ctx instance
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* Config SSL ctx for ssl connection */
    ClientConfigCTX(ctx);

    /* Create a socket for tcp communication */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    /* Initialize the address and port information of the server (opposite party) */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    const char* addressIP = "127.0.0.1"   ;
    const char* portNumber = "7838";
    dest.sin_port = htons(atoi(portNumber));
    if (inet_aton(addressIP, (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        perror(addressIP);
        exit(errno);
    }
    printf("address created\n");

    /* Connect to server */
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");

    /* A new SSL based on ctx */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    /* Establish SSL connection */
    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }

    /* Receive messages sent by the other party, Max buf bytes at most */
    bzero(buffer, MAXBUF + 1);
    /* Receive message from server */
    len = SSL_read(ssl, buffer, MAXBUF);
    if (len > 0)
        printf("Message received successfully:'%s'，common%d Bytes of data\n",
               buffer, len);
    else {
        printf
            ("Message reception failed! The error code is%d，The error message is'%s'\n",
             errno, strerror(errno));
        goto finish;
    }
    bzero(buffer, MAXBUF + 1);
    strcpy(buffer, "from client->server");
    /* Send message to server */
    len = SSL_write(ssl, buffer, strlen(buffer));
    if (len < 0)
        printf
            ("news'%s'Sending failed! The error code is%d，The error message is'%s'\n",
             buffer, errno, strerror(errno));
    else
        printf("news'%s'Sent successfully, sent in total%d Byte!\n",
               buffer, len);

  finish:
    /* Close connection */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
