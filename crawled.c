#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>

#define SUCCESS  0
#define ERR_BASE 0
#define ERR_SSL_READ        ERR_BASE-1
#define ERR_ALREADY_CRAWLED ERR_BASE-2
#define ERR_CREATE_DIR      ERR_BASE-3
#define ERR_GETADDRIFO      ERR_BASE-4
#define ERR_SOCKET          ERR_BASE-5
#define ERR_CONNECT         ERR_BASE-6
#define ERR_OF_ARGS         ERR_BASE-7
#define ERR_OUT_OF_MEM      ERR_BASE-8
#define ERR_FETCH_URL       ERR_BASE-9

#define MAX_URLS 1000
#define OUTPUT_DIR "crawled_pages"
#define BUFFER_SIZE 4096
#define HOST_SIZE 256
#define PATH_SIZE 256
#define PORT_SIZE 10
#define REQUEST_SIZE 512
#define MAX_DEPTH 2


char *crawled_urls[MAX_URLS];
int crawled_count = 0;

int already_crawled(const char *url) {

    for (int i = 0; i < crawled_count; i++) {
        if (strcmp(crawled_urls[i], url) == 0) {
            return ERR_ALREADY_CRAWLED;
        }
    }
    if (crawled_count < MAX_URLS) {
        crawled_urls[crawled_count] = strdup(url);
        crawled_count++;
        return SUCCESS;
    }

    return ERR_ALREADY_CRAWLED;
}

int create_directory(const char *dir_name) {
    struct stat st = {0};
    if (stat(dir_name, &st) == -1) {
        if (mkdir(dir_name, 0700) == -1) {
            fprintf(stderr, "Failed to create directory %s: %s\n", dir_name, strerror(errno));
            return ERR_CREATE_DIR;
        }
    }

    return SUCCESS;
}

char *sanitize_filename(const char *url) {
    char *filename = malloc(strlen(url) + 1);
    int i, j = 0;
    for (i = 0; url[i]; i++) {
        if (url[i] == '/' || url[i] == ':' || url[i] == '?' || url[i] == '&' || url[i] == '=') {
            filename[j++] = '_';
        } else {
            filename[j++] = url[i];
        }
    }
    filename[j] = '\0';
    return filename;
}

SSL_CTX *create_ssl_context() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context.\n");
        return NULL;
    }

    return ctx;
}

int create_socket(const char *hostname, const char *port) {
    struct addrinfo hints, *result, *rp;
    int sockfd = -1;
    int ret_code = SUCCESS;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port, &hints, &result) != 0) {
        return ERR_GETADDRIFO;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            ret_code = ERR_SOCKET;
            continue;
        }

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1) {
            ret_code = SUCCESS;
            break;
        }

        close(sockfd);
        sockfd = -1;
        ret_code = ERR_CONNECT;
    }

    if (rp == NULL) {
        ret_code = ERR_CONNECT;
    }

    freeaddrinfo(result);
    return ret_code == SUCCESS ? sockfd : ret_code;
}

int SSL_read_line(SSL *ssl, char *buffer, int size) {
    int i = 0;
    while (i < size - 1) {
        int result = SSL_read(ssl, buffer + i, 1);
        if (result <= 0) {
            return ERR_SSL_READ;
        }
        if (buffer[i] == '\n') {
            buffer[i + 1] = '\0';
            return 1;
        }
        i++;
    }
    buffer[i] = '\0';
    return SUCCESS;
}

int parse_html(const char *html_content, const char *base_url, char *urls[], int *url_count) {
    const char *a_tag_start = "<a href=";
    const char *pos = html_content;

    char hostname[HOST_SIZE] = "";
    char path[PATH_SIZE] = "";

    const char *start_of_path = strchr(base_url + strlen("https://"), '/');
    if (start_of_path) {
        size_t host_len = start_of_path - (base_url + strlen("https://"));
        strncpy(hostname, base_url + strlen("https://"), host_len);
        hostname[host_len] = '\0';
        
        while (*start_of_path == '/') start_of_path++;
        strcpy(path, start_of_path);

        char *first_slash = strchr(path, '/');
        if (first_slash) {
            *first_slash = '\0';
        }
    }

    while ((pos = strstr(pos, a_tag_start)) != NULL && *url_count < MAX_URLS) {
        pos = strstr(pos, a_tag_start);
        if (pos == NULL) {
            break;
        }

        pos += strlen(a_tag_start);

        char quote_char = '\0';
        if (*pos == '"' || *pos == '\'') {
            quote_char = *pos;
            pos++;
        }

        const char *end;
        if (quote_char) {
            end = strchr(pos, quote_char);
        } else {
            end = strpbrk(pos, " >");
        }

        if (end == NULL) {
            break;
        }

        size_t href_length = end - pos;
        char *href = malloc(href_length + 1);
        strncpy(href, pos, href_length);
        href[href_length] = '\0';

        char *full_url = malloc(strlen(base_url) + strlen(href) + 2);
        if (strncmp(href, "http", 4) == 0) {
            strcpy(full_url, href);
        } else {
            sprintf(full_url, "https://%s/%s/%s", hostname, path, href);
        }

        printf("Found link: %s\n", full_url);
        urls[(*url_count)++] = full_url;

        free(href);
        pos = end + 1;
    }

    return SUCCESS;
}

int read_response(int is_https, SSL *ssl, int sockfd, char **response, size_t *response_len) {
    char buffer[BUFFER_SIZE];
    int bytes, is_chunked = 0;
    char *chunk_start, *chunk_end;
    size_t chunk_size;

    *response = NULL;
    *response_len = 0;

    while ((bytes = (is_https ? SSL_read(ssl, buffer, sizeof(buffer)) : recv(sockfd, buffer, sizeof(buffer), 0))) > 0) {
        *response = realloc(*response, *response_len + bytes + 1);
        if (*response == NULL) {
            fprintf(stderr, "Memory allocation error\n");
            if (is_https) {
                SSL_free(ssl);
            }
            close(sockfd);
            return ERR_OUT_OF_MEM;
        }
        memcpy(*response + *response_len, buffer, bytes);
        *response_len += bytes;
        (*response)[*response_len] = '\0';

        if (strstr(*response, "Transfer-Encoding: chunked")) {
            is_chunked = 1;
        }
    }

    if (is_chunked) {
        printf("Chunked detect\n");
        char *decoded_response = NULL;
        size_t decoded_len = 0;

        chunk_start = strstr(*response, "\r\n\r\n");
        if (chunk_start) {
            chunk_start += 4;

            while (1) {
                chunk_size = strtol(chunk_start, &chunk_end, 16);
                if (chunk_size == 0) {
                    break;
                }
                chunk_end += 2;

                decoded_response = realloc(decoded_response, decoded_len + chunk_size + 1);
                if (decoded_response == NULL) {
                    fprintf(stderr, "Memory allocation error\n");
                    if (is_https) {
                        SSL_free(ssl);
                    }
                    close(sockfd);
                    free(*response);
                    return ERR_OUT_OF_MEM;
                }

                memcpy(decoded_response + decoded_len, chunk_end, chunk_size);
                decoded_len += chunk_size;
                chunk_end += chunk_size + 2;

                chunk_start = chunk_end;
            }
            decoded_response[decoded_len] = '\0';

            free(*response);
            *response = decoded_response;
            *response_len = decoded_len;
        }
    }

    return SUCCESS;
}

char *fetch_url(const char *url, SSL_CTX *ctx, int depth, char **final_url, int count) {
    if (count > 5) {
        fprintf(stderr, "Max depth reached\n");
        return NULL;
    }

    char hostname[HOST_SIZE] = "";
    char path[PATH_SIZE] = "";
    char port[PORT_SIZE] = "";
    int is_https = 0;
    if (strncmp(url, "http://", 7) == 0) {
        sscanf(url, "http://%255[^:/]/%255[^\n]", hostname, path);
    } else if (strncmp(url, "https://", 8) == 0) {
        sscanf(url, "https://%255[^/]/%255[^\n]", hostname, path);
        is_https = 1;
    } else {
        fprintf(stderr, "Invalid URL scheme\n");
        return NULL;
    }

    is_https == 0 ? strcpy(port, "80") : strcpy(port, "443");
    if (strlen(path) == 0) strcpy(path, "/");
    int sockfd = create_socket(hostname, port);
    if (sockfd < 0) {
        return NULL;
    }

    char *response = NULL;
    size_t response_len = 0;
    char *new_location = NULL;
    char buffer[BUFFER_SIZE];
    int bytes;
    int is_chunked = 0;

    char request[REQUEST_SIZE];
    snprintf(request, sizeof(request),
            "GET /%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: curl/7.64.1\r\n"
            "Connection: close\r\n\r\n", path, hostname);

    if (is_https) {
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);
        SSL_set_tlsext_host_name(ssl, hostname);
        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(sockfd);
            return NULL;
        }
        
        SSL_write(ssl, request, strlen(request));
        read_response(1, ssl, sockfd, &response, &response_len);
        SSL_free(ssl);
    } else {
        send(sockfd, request, strlen(request), 0);
        read_response(0, NULL, sockfd, &response, &response_len);
    }

    close(sockfd);


    int status_code = -1;
    sscanf(response, "HTTP/1.1 %d", &status_code);
    if (status_code == -1) {
        printf("HTTP Status Code: 200\n");
    } else {
        printf("HTTP Status Code: %d\n", status_code);
    }

    if (status_code == 301 || status_code == 302) {
        char *location = strstr(response, "Location: ");
        if (location) {
            location += 10;
            char *end = strchr(location, '\r');
            if (!end) {
                end = strchr(location, '\n');
            }
            if (end) {
                new_location = strndup(location, end - location);
                char *redirect_url;
                if (new_location[0] == '/') {
                    char base_url[256];
                    snprintf(base_url, sizeof(base_url), "%s://%s", is_https ? "https" : "http", hostname);
                    redirect_url = malloc(strlen(base_url) + strlen(new_location) + 1);
                    strcpy(redirect_url, base_url);
                    strcat(redirect_url, new_location);
                } else {
                    redirect_url = strdup(new_location);
                }
                printf("Redirecting to: %s\n", redirect_url);
                char *redirect_response = fetch_url(redirect_url, ctx, depth, final_url, count + 1);
                free(response);
                free(redirect_url);
                free(new_location);
                return redirect_response;
            }
        }
    }

    *final_url = strdup(url);

    return response;
}

int fetch_and_parse(char *url, int depth, SSL_CTX *ctx) {

    if (already_crawled(url) != 0) {
        printf("URL already crawled: %s\n", url);
        return ERR_ALREADY_CRAWLED;
    }

    printf("Connecting to %s...\n", url);
    int count = 0;
    char *final_url = NULL;
    char *response = fetch_url(url, ctx, depth, &final_url, count);
    if (!response) {
        fprintf(stderr, "Failed to fetch URL: %s\n", url);
        return ERR_FETCH_URL;
    }
    
    if (strcmp(url, final_url) != 0) {
        url = strdup(final_url);
    }

    if (strstr(response, "Content-Type: application/pdf")) {
        char *header_end = strstr(response, "\r\n\r\n");
        if (header_end) {
            header_end += 4;
            char *pdf_filename = sanitize_filename(url);
            char pdf_path[BUFFER_SIZE];
            snprintf(pdf_path, sizeof(pdf_path), "%s/depth_%d_%s", OUTPUT_DIR, depth, pdf_filename);
            free(pdf_filename);

            char *content_length_str = strstr(response, "Content-Length: ");
            size_t content_length = 0;
            if (content_length_str) {
                content_length_str += strlen("Content-Length: ");
                content_length = strtoul(content_length_str, NULL, 10);
            }

            FILE *pdf_fp = fopen(pdf_path, "wb");
            if (pdf_fp) {
                fwrite(header_end, 1, content_length, pdf_fp);
                fclose(pdf_fp);
                printf("PDF saved to %s\n", pdf_path);
            }
        }
    } else if (strstr(response, "Content-Type: image/jpeg")) {
        char *header_end = strstr(response, "\r\n\r\n");
        if (header_end) {
            header_end += 4;
            char *image_filename = sanitize_filename(url);
            char image_path[BUFFER_SIZE];
            snprintf(image_path, sizeof(image_path), "%s/depth_%d_%s", OUTPUT_DIR, depth, image_filename);
            free(image_filename);

            char *content_length_str = strstr(response, "Content-Length: ");
            size_t content_length = 0;
            if (content_length_str) {
                content_length_str += strlen("Content-Length: ");
                content_length = strtoul(content_length_str, NULL, 10);
            }

            FILE *image_fp = fopen(image_path, "wb");
            if (image_fp) {
                fwrite(header_end, 1, content_length, image_fp);
                fclose(image_fp);
                printf("Image saved to %s\n", image_path);
            }
        }
    } else {
        char *body_start = strstr(response, "<body");
        if (body_start) {
            body_start = strchr(body_start, '>');
            if (body_start) {
                body_start += 1;
            }
        } else {
            body_start = response;
        }

        char *body_end = strstr(body_start, "</body>");
        if (body_end) {
            *body_end = '\0';
        }
        
        char filename[BUFFER_SIZE];
        char *safe_filename = sanitize_filename(url);
        snprintf(filename, sizeof(filename), "%s/depth_%d_%s.html", OUTPUT_DIR, depth, safe_filename);
        free(safe_filename);
        FILE *fp = fopen(filename, "wb");
        if (fp) {
            fwrite(body_start, 1, strlen(body_start), fp);
            fclose(fp);
            printf("Response saved to %s\n", filename);
        }
    }

    if (depth < MAX_DEPTH) {
        char *urls[MAX_URLS];
        int url_count = 0;
        char *img_urls[MAX_URLS];
        int img_url_count = 0;
        parse_html(response, url, urls, &url_count);

        for (int i = 0; i < url_count; i++) {
            fetch_and_parse(urls[i], depth + 1, ctx);
            free(urls[i]);
        }
    }

    free(response);
    return SUCCESS;
}

int main(int argc, char *argv[]) {
    // Test url = "https://www.openfind.com.tw/taiwan/news_detail.php?news_id=10335"
    // Test url = "https://www.openfind.com.tw/taiwan/news_detail.php?news_id=10334"
    // Test url = "https://www.openfind.com.tw/taiwan/news_detail.php?news_id=10339"
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <start URL> <output directory>\n", argv[0]);
        return ERR_OF_ARGS;
    }

    char *start_url = argv[1];
    const char *output_dir = argv[2];

    SSL_CTX *ctx = create_ssl_context();
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return EXIT_FAILURE;
    }

    create_directory(output_dir);
    fetch_and_parse(start_url, 1, ctx);

    SSL_CTX_free(ctx);
    EVP_cleanup();
    return SUCCESS;
}
