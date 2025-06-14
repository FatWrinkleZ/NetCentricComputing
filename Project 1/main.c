#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdbool.h>

#define MAX_URL_SIZE 2000
#define BUFFER_SIZE 1024

typedef struct HTTP_REQ {
    char host[BUFFER_SIZE];
    char path[BUFFER_SIZE];
    const char *port;
    struct addrinfo hints, *result, *rp;
    char buffer[BUFFER_SIZE];
    int sfd;
    uint8_t exists;
    uint8_t is_https;
    SSL *ssl;
    SSL_CTX *ctx;
} HTTP_REQ;

HTTP_REQ generateRequest(const char*);
void processBuffer(int, char*);
int processRequest(HTTP_REQ, bool);
char* getRefUrl(char* body);

char* getRefUrl(char* body){
    static char outUrl[MAX_URL_SIZE];
    char *url_start=NULL, *url_end=NULL;
    url_start=strstr(body, "src=");
    if (url_start == NULL){return NULL;}
    //printf("FOUND LINK\n");
    url_start+=5;
    for (char* i = url_start; i < url_start+MAX_URL_SIZE; i++){
        if(*i == '"'){
            url_end = i;
            break;
        }
    }
    int len = (url_end - url_start)+1;
    snprintf(outUrl, len, "%s", url_start);
    return outUrl;
}

HTTP_REQ generateRequest(const char *URL) {
    HTTP_REQ req = {0};
    req.port = "80";
    req.is_https = 0;

    char buf[MAX_URL_SIZE];
    char* url_clean = &buf[0];
    strncpy(url_clean, URL, MAX_URL_SIZE - 1);
    url_clean[MAX_URL_SIZE - 1] = '\0';
    while (*url_clean == ' ') url_clean++;
    char *newline = strchr(url_clean, '\n');
    if (newline) *newline = '\0';

    const char *url_start = url_clean;
    if (strncmp(url_clean, "http://", 7) == 0) {
        url_start += 7;
        req.port = "80";
    } else if (strncmp(url_clean, "https://", 8) == 0) {
        url_start += 8;
        req.port = "443";
        req.is_https = 1;
    } else {
        req.port = "80";
    }

    char *path_start = strchr(url_start, '/');
    if (path_start && path_start[1] != '\0') {
        strncpy(req.path, path_start + 1, BUFFER_SIZE - 1);
        req.path[BUFFER_SIZE - 1] = '\0';
        size_t host_len = path_start - url_start;
        if (host_len >= BUFFER_SIZE) host_len = BUFFER_SIZE - 1;
        strncpy(req.host, url_start, host_len);
        req.host[host_len] = '\0';
    } else {
        strncpy(req.host, url_start, BUFFER_SIZE - 1);
        req.host[BUFFER_SIZE - 1] = '\0';
        size_t host_len = strlen(req.host);
        if (host_len > 0 && req.host[host_len - 1] == '/') {
            req.host[host_len - 1] = '\0';
        }
        req.path[0] = '\0';
    }

    //printf("Parsed host: %s, path: %s, port: %s, is_https: %d\n", req.host, req.path, req.port, req.is_https);

    req.hints.ai_family = AF_UNSPEC;
    req.hints.ai_socktype = SOCK_STREAM;
    req.hints.ai_flags = 0;
    req.hints.ai_protocol = 0;

    int addr_err = getaddrinfo(req.host, req.port, &req.hints, &req.result);
    if (addr_err != 0) {
        //fprintf(stderr, "getaddrinfo failed for host '%s': %s\n", req.host, gai_strerror(addr_err));
        req.exists = 0;
    } else {
        req.exists = 1;
    }

    return req;
}

void processBuffer(int status, char* buffer){
    int tmp=0;
    printf("Status: %d ", status);
    char buffer_str[BUFFER_SIZE];
    sscanf(buffer, "HTTP/1.1 %d %[^\n]", &tmp, buffer_str);
    printf("%s\n", buffer_str);
    if(status / 100 == 3){
        char* locationLine = strstr(buffer, "Location:");
        if(locationLine){
            sscanf(locationLine, "Location: %[^\n]", buffer_str);
            printf("Redirected Url: %s\n", buffer_str);
            HTTP_REQ req = generateRequest(buffer_str);
            processRequest(req, false);
        }else{
            printf("Could not find redirect URL\n");
        }
    }

}

int processRequest(HTTP_REQ req, bool GET) {
    if (!req.exists) {
        printf("Status: Network Error (DNS resolution failed)\n");
        return -1;
    }

    for (req.rp = req.result; req.rp != NULL; req.rp = req.rp->ai_next) {
        req.sfd = socket(req.rp->ai_family, req.rp->ai_socktype, req.rp->ai_protocol);
        if (req.sfd == -1) {
            perror("Error creating socket");
            continue;
        }
        if (connect(req.sfd, req.rp->ai_addr, req.rp->ai_addrlen) != -1) {
            break;
        }
        perror("Error connecting to host");
        close(req.sfd);
    }

    if (req.rp == NULL) {
        printf("Status: Network Error (connection failed)\n");
        freeaddrinfo(req.result);
        return -1;
    }

    freeaddrinfo(req.result);

    if (req.is_https) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        req.ctx = SSL_CTX_new(TLS_client_method());
        if (!req.ctx) {
            fprintf(stderr, "Error creating SSL context\n");
            close(req.sfd);
            return -1;
        }

        req.ssl = SSL_new(req.ctx);
        if (!req.ssl) {
            fprintf(stderr, "Error creating SSL object\n");
            SSL_CTX_free(req.ctx);
            close(req.sfd);
            return -1;
        }

        if (!SSL_set_fd(req.ssl, req.sfd)) {
            fprintf(stderr, "Error setting SSL file descriptor\n");
            SSL_free(req.ssl);
            SSL_CTX_free(req.ctx);
            close(req.sfd);
            return -1;
        }

        SSL_set_tlsext_host_name(req.ssl, req.host);

        if (SSL_connect(req.ssl) != 1) {
            fprintf(stderr, "Error performing TLS handshake: %s\n", ERR_error_string(ERR_get_error(), NULL));
            SSL_free(req.ssl);
            SSL_CTX_free(req.ctx);
            close(req.sfd);
            return -1;
        }
    }

    char sendline[BUFFER_SIZE];
    if(!GET){
        snprintf(sendline, BUFFER_SIZE, 
            "HEAD /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", 
            req.path[0] ? req.path : "", req.host);
    }else{
        snprintf(sendline, BUFFER_SIZE, 
            "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", 
            req.path[0] ? req.path : "", req.host);
    }

    if (req.is_https) {
        if (SSL_write(req.ssl, sendline, strlen(sendline)) <= 0) {
            fprintf(stderr, "Error sending HTTPS request: %s\n", ERR_error_string(ERR_get_error(), NULL));
            SSL_free(req.ssl);
            SSL_CTX_free(req.ctx);
            close(req.sfd);
            return -1;
        }
    } else {
        if (write(req.sfd, sendline, strlen(sendline)) < 0) {
            perror("Error sending HTTP request");
            close(req.sfd);
            return -1;
        }
    }

    memset(req.buffer, 0, BUFFER_SIZE);
    int bytes_received = req.is_https ? SSL_read(req.ssl, req.buffer, BUFFER_SIZE - 1) : read(req.sfd, req.buffer, BUFFER_SIZE - 1);
    if (bytes_received < 0) {
        fprintf(stderr, "Error receiving response: %s\n", req.is_https ? ERR_error_string(ERR_get_error(), NULL) : strerror(errno));
        if (req.is_https) {
            SSL_free(req.ssl);
            SSL_CTX_free(req.ctx);
        }
        close(req.sfd);
        return -1;
    }
    req.buffer[bytes_received] = '\0';

    int status_code = 0;
    if (!GET){
        if (strncmp(req.buffer, "HTTP/", 5) == 0) {
            char *status_start = strchr(req.buffer, ' ') + 1;
            if (status_start) {
                status_code = atoi(status_start);
                processBuffer(status_code, req.buffer);
                //printf("Rest of buffer: %s\n", req.buffer);
            } else {
                printf("Status: Error (invalid response format)\n");
            }
        } else {
            printf("Status: Error (non-HTTP response)\n");
        }
    }else{
        char* refLink = getRefUrl(req.buffer);
        if(refLink){
            char url_buffer[MAX_URL_SIZE];
            url_buffer[0]='\0';
            if(refLink[0]=='/'){
                sprintf(url_buffer, "%s%s",req.host, refLink);
            }else{
                strcpy(url_buffer, refLink);
            }
            printf("Referenced URL: %s\n", url_buffer);
            HTTP_REQ req = generateRequest(url_buffer);
            processRequest(req, false);
        }
        //puts(req.buffer);
    }

    if (req.is_https) {
        SSL_free(req.ssl);
        SSL_CTX_free(req.ctx);
    }
    shutdown(req.sfd, SHUT_RDWR);
    close(req.sfd);
    return status_code;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Error: usage '%s' path_to_url_file\n", argv[0]);
        exit(1);
    }

    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    char url_buffer[MAX_URL_SIZE];
    while (fgets(url_buffer, MAX_URL_SIZE, file)) {
        //printf("<====NEW LINK====>\n");
        url_buffer[strcspn(url_buffer, "\n")] = '\0';
        printf("URL: %s\n", url_buffer);
        HTTP_REQ req = generateRequest(url_buffer);
        int retStat = processRequest(req,false);
        if(retStat == 200){
            HTTP_REQ getReq = generateRequest(url_buffer);
            processRequest(getReq, true);
        }
        puts("");
    }

    fclose(file);
    return 0;
}