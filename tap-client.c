#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

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

#include "keystore_request.h"
#include "command_line.h"
#include "./ed25519/ed25519.h"

#if defined(DEBUG_TAP)
#define DEBUG_PRINT(fmt, args...)    fprintf(stderr, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args...)    
#endif


void usage() {
	printf("./tap_client <request> <request_file> <hostname> <port>\n request = {reg_user, reg_rule, update_rule}\n");
}

#define derBufSz 8000
#define MAX_FILE_SIZE 65535

char filebuffer[MAX_FILE_SIZE];
static char pub_key[2048];

int myCustomExtCallback(const word16* oid, word32 oidSz, int crit,
                               const unsigned char* der, word32 derSz) {
    word32 i;

    printf("Custom Extension found!\n");
    
    report_t report;
    memcpy((void *)&report, der, sizeof(report_t));


    // Verify the signature here and later check if the public key matches that in the certificate
    if (ed25519_verify((unsigned char *)&report.enclave.signature, (unsigned char *)&report.enclave, 
        sizeof(struct enclave_report_t) - ATTEST_DATA_MAXLEN - SIGNATURE_SIZE + report.enclave.data_len, (unsigned char *)&report.sm.public_key)) {
        printf("[Custom Extension] Successfully verified signature!\n");
    } else {
        printf("[Custom Extension] Successfully verified signature!\n");
    }

    // Store the DER public key for later verification
    printf("[Custom Extension] report.enclave.data_len: %lu\n", report.enclave.data_len);
    memcpy((void *)&pub_key, (void *)&report.enclave.data, report.enclave.data_len);
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
    int ret;
    //char *derbuf = (char *)malloc(8000 * sizeof(char));

    unsigned char *derBuffer[1];
    derBuffer[0] = NULL;

    int derSz = wolfSSL_i2d_X509(current_cert, derBuffer);
    fflush(stdout);
    wc_InitDecodedCert(decodedCert, derBuffer[0], derSz, 0);
    
    wc_SetUnknownExtCallback(decodedCert, myCustomExtCallback);

    ret = ParseCert(decodedCert, CERT_TYPE, NO_VERIFY, NULL);
    if (ret == 0) {
        printf("[verify_attested_tls] Cert issuer: %s\n", decodedCert->issuer);
    }


    if (memcmp(decodedCert->publicKey, pub_key, decodedCert->pubKeySize) == 0) {
        printf("[verify_attested_tls] Public Keys Match!\n");
    } else {
        printf("[verify_attested_tls] Public Keys Do Not Match!\n");
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

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = *((struct in_addr *)hostnm->h_addr_list[0]);

	if (connect(fd_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0 ) {
		printf("[init] connect error");
		exit(-1);
	}

	return fd_sock;
}

uint64_t write_buffer(WOLFSSL *sslserv, void *buffer, size_t sz)
{
    uint64_t pos = 0;
    int64_t ret = wolfSSL_write(sslserv, buffer, sz);
    int error;

    while (ret > 0) {
        pos += ret;
        if (pos == sz) {
            return pos;
        }
        ret = wolfSSL_write(sslserv, (void *) (buffer + pos), sz - pos);
    }

    error = wolfSSL_get_error(sslserv, 0);
    if (ret < 0) {
        if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                printf("server write failed\n");
        }
    }

    return pos;
}

// Reads till a null byte is encountered
uint64_t read_buffer(WOLFSSL *sslcli, void *buffer, size_t sz)
{
	uint64_t pos = 0;
	int64_t ret = wolfSSL_read(sslcli, buffer, sz);
    int error;

	while (ret > 0) {
		pos += ret;
        if (pos == sz) {
            return pos;
        }
		ret = wolfSSL_read(sslcli, (void *) (buffer + pos), sz - pos);
	}

    error = wolfSSL_get_error(sslcli, 0);
    if (ret < 0) {
        if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                printf("server read failed\n");
        }
    }

	return pos;
}

int64_t send_message(WOLFSSL *sslcli, void *buffer, size_t sz) {
    uint64_t request_sz = sz;
    write_buffer(sslcli, &request_sz, sizeof(uint64_t));
    int64_t ret = write_buffer(sslcli, buffer, sz);
    return ret;
}

int64_t recv_message(WOLFSSL *sslcli, void *buffer, size_t sz) {
    uint64_t request_sz;
    read_buffer(sslcli, &request_sz, sizeof(uint64_t));
    DEBUG_PRINT("Receiving message of size: %lu\n", request_sz);

    int64_t ret = read_buffer(sslcli, buffer, request_sz);
    return ret;
}

char *parse_file(char *filebuffer, char *delim) {
    int l = strlen(delim);
    char *pattern_start = strstr(filebuffer, delim) + l;
    while (isspace(*pattern_start)) {
        pattern_start = pattern_start + 1;
    }

    char *st = pattern_start;
    char *end = pattern_start;
    while(*end != '\n') {
        end = end + 1;
    }

    end = end - 1;
    int sz = end - st + 1;
    char *ret = (char *)malloc((sz + 1) * sizeof(char));

    int i = 0;
    for(; i < sz; i++) {
        ret[i] = st[i];
    }

    ret[i] = 0;
    return ret;
}

char *hex_to_bytes(char *hexstring, int len_out) {
    char *pos = hexstring;
    char *ret = (char *)malloc(len_out * sizeof(char));
    for (size_t count = 0; count < len_out; count++) {
        sscanf(pos, "%2hhx", &ret[count]);
        pos += 2;
    }

    return ret;
}

struct option parse_command_line(int argc, char **argv) {
    struct option opt;
    opt.invalid = 0;

    if (argc != 5) {
        opt.invalid = 1;
        return opt;
    }

    FILE *fp = fopen(argv[2], "r+");
    if (!fp) {
        opt.invalid = 1;
        return opt;
    }

    int fsize = fread(filebuffer, 1, MAX_FILE_SIZE, fp);
    if (fsize == MAX_FILE_SIZE) {
        opt.invalid = 1;
        return opt;
    }

    if (strcmp(argv[1], "reg_rule") == 0) {
        opt.req_type = REQ_REGRULE;
        regrule_request_t regrule_req;
        memset(&regrule_req, 0, sizeof(regrule_request_t));

        char *username = parse_file(filebuffer, "username:");
        strncpy(regrule_req.username, username, 20);

        char *password = parse_file(filebuffer, "password:");
        strncpy(regrule_req.password, password, 20);

        DEBUG_PRINT("Username: %s, Password: %s\n", username, password);

        char *num_triggers = parse_file(filebuffer, "num_triggers:");
        char *num_actions = parse_file(filebuffer, "num_actions:");
        char *rid = parse_file(filebuffer, "rid:");

        int nt = atoi(num_triggers);
        int na = atoi(num_actions);

        regrule_req.num_triggers = nt;
        regrule_req.num_actions = na;


        char key_delim[40];
        for(int i = 0; i < nt; i++) {
            snprintf(key_delim, 40, "trigger%d_key:", i);
            char *trigger_key_hex = parse_file(filebuffer, key_delim);
            char *trigger_key = hex_to_bytes(trigger_key_hex, TRIGGER_KEY_SIZE);
            memcpy(regrule_req.key_trigger[i], trigger_key, TRIGGER_KEY_SIZE);
        }

        for(int i = 0; i < na; i++) {
            snprintf(key_delim, 40, "action%d_key:", i);
            char *action_key_hex = parse_file(filebuffer, key_delim);
            char *action_key = hex_to_bytes(action_key_hex, ACTION_KEY_SIZE);
            memcpy(regrule_req.key_action[i], action_key, ACTION_KEY_SIZE);
        }


        char *rule_key_hex = parse_file(filebuffer, "rule_key:");
        char *rule_key = hex_to_bytes(rule_key_hex, RULE_KEY_SIZE);
        memcpy(regrule_req.key_rule, rule_key, RULE_KEY_SIZE);

        char *rule_bin_hash_hex = parse_file(filebuffer, "rule_bin_hash:");
        char *rule_bin_hash = hex_to_bytes(rule_bin_hash_hex, EAPP_BIN_HASH_SIZE);
        memcpy(regrule_req.rule_bin_hash, rule_bin_hash, EAPP_BIN_HASH_SIZE);

        char *sm_bin_hash_hex = parse_file(filebuffer, "sm_bin_hash:");
        char *sm_bin_hash = hex_to_bytes(sm_bin_hash_hex, SM_BIN_HASH_SIZE);
        memcpy(regrule_req.sm_bin_hash, sm_bin_hash, SM_BIN_HASH_SIZE);

        //opt.req_type = REGRULE_REQUEST;
        opt.request.type = REGRULE_REQUEST;
        opt.request.data.regrule_req = regrule_req;

    } else if (strcmp(argv[1], "reg_user") == 0) {
        opt.req_type = REQ_REGUSER;
        char *username = parse_file(filebuffer, "username:");
        char *password = parse_file(filebuffer, "password:");

        DEBUG_PRINT("Username: %s, Password: %s\n", username, password);
        
        reguser_request_t reguser_req;
        memset(&reguser_req, 0, sizeof(reguser_req));

        strncpy((char *)&reguser_req.username, username, USERNAME_SIZE - 1);
        strncpy((char *)&reguser_req.password, password, PASSWORD_SIZE - 1);

        reguser_req.user_len = strlen(reguser_req.username);
        reguser_req.user_len = strlen(reguser_req.password);

        opt.request.type = REGUSER_REQUEST;
        opt.request.data.reguser_req = reguser_req;

    } else if (strcmp(argv[1], "update_rule") == 0) {


    }

    opt.hostname = strdup(argv[3]);
    opt.port = atoi(argv[4]);

    return opt;
}

int main(int argc, char **argv)
{
    clock_t start, end;
    double cpu_time_used;
    start = clock();

    char reply[65535];
    int ret, msgSz, sockfd;
    struct sockaddr_in servAddr;
    WOLFSSL* sslCli;
    WOLFSSL_CTX* ctxCli = NULL;

    struct option opt = parse_command_line(argc, argv);

    if (opt.invalid == 1) {
        usage();
        return -1;
    }

    wolfSSL_Init();

    //TODO: Fix test here!
    char *hostname = opt.hostname;
    int port = opt.port;
    //int host_len = strlen(hostname);

    sslCli = Client(ctxCli, "let-wolfssl-decide", 0);
    sockfd = initiate_connection(hostname, port);

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
                fflush(stdout);
                goto cleanup;
            }
        }
        printf("Client connected successfully...\n");
    }

    send_message(sslCli, &opt.request, sizeof(opt.request));
    int sz = recv_message(sslCli, reply, sizeof(reply));
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Reply: %s, Reply size: %d\n", reply, sz);
    printf("CPU Time Used: %lf\n", cpu_time_used);
    
/*
    switch (opt.req_type) {
        case REQ_REGUSER:
                send_message(sslCli, &opt.request, sizeof(opt.request));
                sz = recv_message(sslCli, reply, sizeof(reply));
                printf("Reply: %s, Reply size: %d\n", reply, sz);
                break;
        case REQ_REGRULE:
                send_message(sslCli, &opt.request.data.regrule_req, sizeof(opt.request.data.regrule_req));
                sz = recv_message(sslCli, reply, sizeof(reply));
                printf("Reply: %s, Reply size: %d\n", reply, sz);
                break;
        default:
                printf("unsupported rule type\n");
                return -1;
    }*/

    /*printf("Sending User registration request\n");
    fflush(stdout);

    reguser_request_t reg;
    memset(&reg, 0, sizeof(reg));

    strncpy(reg.username, "bug", 4);
    strncpy(reg.password, "bug", 4);

    reg.password_len = 3;
    reg.user_len = 3;

    request_t request;
    request.type = REGUSER_REQUEST;
    request.data.reguser_req = reg;

    send_message(sslCli, &request, sizeof(request));
    int sz = recv_message(sslCli, reply, sizeof(reply));

    printf("Reply: %s, Reply size: %d\n", reply, sz);*/

    /*request_t request_2;
    request_2.type = RUNTIME_REQUEST;
    runtime_request_t runtime_req;
    request_2.data.runtime_req = runtime_req;

    send_message(sslCli, &request_2, sizeof(request_2));
    sz = recv_message(sslCli, reply, sizeof(reply));

    printf("Reply2: %s, Reply size: %d\n", reply, sz);*/


    /*(regrule_request_t regrule;
    memset(&regrule, 0, sizeof(regrule_request_t));
    regrule.rid = 1;
    regrule.num_triggers = regrule.num_actions = 1;
    strncpy_s(regrule.username, "bug", 4);
    strncpy(regrule.username, "bug", 4);*/





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
