#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/asn.h>

void usage() {
	printf("./tap_client <request> <request_params>");
}

#define derBufSz 8000

int myCustomExtCallback(const word16* oid, word32 oidSz, int crit,
                               const unsigned char* der, word32 derSz) {
    word32 i;

    printf("Custom Extension found!\n");
    printf("(");
    for (i = 0; i < oidSz; i++) {
        printf("%d", oid[i]);
        if (i < oidSz - 1) {
            printf(".");
        }
    }
    printf(") : ");

    if (crit) {
        printf("CRITICAL");
    } else {
        printf("NOT CRITICAL");
    }
    printf(" : ");

    for (i = 0; i < derSz; i ++) {
        printf("%x ", der[i]);
    }
    printf("\n");
    fflush(stdout);

    /* NOTE: by returning zero, we are accepting this extension and informing
     *       wolfSSL that it is acceptable. If you find an extension that you
     *       do not find acceptable, you should return an error. The standard 
     *       behavior upon encountering an unknown extension with the critical
     *       flag set is to return ASN_CRIT_EXT_E. For the sake of brevity,
     *       this example is always accepting every extension; you should use
     *       different logic. */
    return 0;
}


int verify_attested_tls(int preverify, WOLFSSL_X509_STORE_CTX* store_ctx) {
    printf("[verify_attested_tls] Entering\n");
	WOLFSSL_X509 *current_cert = store_ctx->current_cert;
	DecodedCert *decodedCert = (DecodedCert *)malloc(sizeof(DecodedCert));
    //char *derbuf = (char *)malloc(8000 * sizeof(char));

    unsigned char *derBuffer[1];
    derBuffer[0] = NULL;

    int derSz = wolfSSL_i2d_X509(current_cert, derBuffer);
    fflush(stdout);
    wc_InitDecodedCert(decodedCert, derBuffer[0], derSz, 0);
    

    int ret = wc_SetUnknownExtCallback(decodedCert, myCustomExtCallback);

    ret = ParseCert(decodedCert, CERT_TYPE, NO_VERIFY, NULL);
    if (ret == 0) {
        printf("[verify_attested_tls] Cert issuer: %s\n", decodedCert->issuer);
    }

    return 1;
}

WOLFSSL* Client(WOLFSSL_CTX* ctx, char* suite, int setSuite)
{
    WOLFSSL* ssl = NULL;
    int ret;

    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        printf("Error in setting client ctx\n");
        return NULL;
    }

    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_attested_tls);
    //wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    if (setSuite == 1) {
        if ((ret = wolfSSL_CTX_set_cipher_list(ctx, suite)) != SSL_SUCCESS) {
            printf("ret = %d\n", ret);
            printf("can't set cipher\n");
            wolfSSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        (void) suite;
    }

    //wolfSSL_SetIORecv(ctx, CbIORecv);
    //wolfSSL_SetIOSend(ctx, CbIOSend);

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        printf("issue when creating ssl\n");
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    return ssl;
}

int32_t initiate_connection(char *hostname, int32_t port) {

	int fd_sock;
	struct sockaddr_in server_addr;
	struct hostent *hostnm;

	fd_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (fd_sock < 0) {
		printf("[init] Failed to open socket\n");
		exit(-1);
	}

	memset(&server_addr, 0, sizeof(server_addr));
	hostnm = gethostbyname(hostname);

	if (hostnm == NULL) {
		printf("[init] Gethostname failed");
		exit(-1);
	}

	server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(port);
    server_addr.sin_addr = *((struct in_addr *)hostnm->h_addr_list[0]);

	if (connect(fd_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0 ) {
		printf("[init] connect error");
		exit(-1);
	}

	return fd_sock;
}

int main(int argc, char **argv)
{
	char msg[] = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    //Not working!: 
    //char msg[] = "GET / HTTP/1.1\r\n";
    char reply[65535];
    int ret, msgSz, sockfd;
    struct sockaddr_in servAddr;
    WOLFSSL* sslCli;
    WOLFSSL_CTX* ctxCli = NULL;
    msgSz = strlen(msg);

    wolfSSL_Init();

    char *hostname = "localhost";
    int host_len = strlen(hostname);

    sslCli = Client(ctxCli, "let-wolfssl-decide", 0);
    sockfd = initiate_connection(hostname, 34563);

    /* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(sslCli, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto cleanup;
    }

    ret = SSL_FAILURE;

    printf("Starting client\n");
    while (ret != SSL_SUCCESS) {
        int error;
        printf("Connecting..\n");
        /* client connect */
        ret |= wolfSSL_connect(sslCli);
        error = wolfSSL_get_error(sslCli, 0);
        if (ret != SSL_SUCCESS) {
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                printf("client ssl connect failed, error: %d\n", error);
                goto cleanup;
            }
        }
        printf("Client connected successfully...\n");
    }



cleanup:
    wolfSSL_free(sslCli);      /* Free the wolfSSL object                  */
ctx_cleanup:
    wolfSSL_CTX_free(ctxCli);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
socket_cleanup:
    close(sockfd);          /* Close the connection to the server       */
end:
    return ret;               /* Return reporting a success               */
    
}