// Author   : xnovak2r
// Date     : Sep 2023
// Subject  : ISA
// Project  : DNS resolver

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <regex.h>

#define A 1     // ipv4
#define AAAA 28 // ipv6

#define ID 255  // any 16-bit number
#define IN 1

#define UDP_PORT 53
#define UDP_MSG_SIZE 512

#define PORT_MIN 0
#define PORT_MAX 65353

#define IPv4_regex "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"

/*                              1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct DNS_Header {
    uint16_t id;
    uint16_t flags;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
};

// TODO: check rfc names
struct DNS_Request {
    unsigned short qtype;
    unsigned short qclass;
};


/// -lresolv in Makefile
int main(int argc, char **argv) {
    char *server, *address;
    int opt, type = A, port = UDP_PORT, sock, addr_info;
    bool rec_desired = false, rev_query = false, addr = false, srv = false;
    struct addrinfo hints, *result;
    struct sockaddr_in *server_addr;

    while ((opt = getopt(argc, argv, "rx6s:p:")) != -1) {
        switch (opt) {
            case 'r':
                rec_desired = true;
                break;

            case 'x':
                rev_query = true;
                break;

            case '6':
                type = AAAA;
                break;

            case 's':
                srv = true;
                server = strdup(optarg);
                if (server == NULL) {
                    fprintf(stderr, "Memory allocation for 'server' failed\n");
                    exit(EXIT_FAILURE);
                }
                break;

            case 'p':
                char *end;
                long p = strtol(optarg, &end, 10);
                if (*end != '\0') {
                    fprintf(stderr, "'port' is not a number\n");
                    fprintf(stderr, "Usage: %s [-r] [-x] [-6] -s server [-p port] address\n", argv[0]);
                    exit(EXIT_FAILURE);
                }
                if (p < PORT_MIN || p > PORT_MAX) {
                    fprintf(stderr, "invalid port number\n");
                    exit(EXIT_FAILURE);
                }
                port = (int)p;
                break;

            case '?':
                fprintf(stderr, "Usage: %s [-r] [-x] [-6] -s server [-p port] address\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    for (int i = optind; i < argc; ++i) {
        if (addr) {
            fprintf(stderr, "got more than 1 address\n");
            fprintf(stderr, "Usage: %s [-r] [-x] [-6] -s server [-p port] address\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        addr = true;
        address = strdup(argv[i]);
        if (server == NULL) {
            fprintf(stderr, "Memory allocation for 'address' failed\n");
            exit(EXIT_FAILURE);
        }
    }

    if (!addr || !srv) {
        fprintf(stderr, "'-s server' and 'address' are required\n");
        fprintf(stderr, "Usage: %s [-r] [-x] [-6] -s server [-p port] address\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    uint16_t id = ID;
    uint16_t flags = 0b0;
    if (rev_query)
        flags += 0b1 << 11;

    if (rec_desired)
        flags += 0b1 << 8;

    uint16_t QDCount = 1;
    uint16_t QDType = type;
    uint16_t QDClass = IN;
    // TODO: change this to real stuff
    uint8_t name[] = {'6', 'g', 'o', 'o', 'g', 'l', 'e', '3', 'c', 'o', 'm'};

    // get server IP address from server name
    /// https://man7.org/linux/man-pages/man3/getaddrinfo.3.html ///
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    addr_info = getaddrinfo(server, NULL, &hints, &result);
    if (addr_info != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(addr_info));
        exit(EXIT_FAILURE);
    }
    ////////////////////////////////////////////////////////////////

    // create socket
    AF_INET;AF_INET6;AF_UNSPEC;
    sock= socket(AF_INET, SOCK_DGRAM, 0); /// AF_INET for ipv4/AF_INET6 for ipv6/AF_UNSPEC for ipv4 or ipv6 ???
    if (sock < 0) {
        fprintf(stderr, "Creation of socket failed\n");
        exit(EXIT_FAILURE);
    }

    // set server info
    server_addr = (struct sockaddr_in*)result->ai_addr;
    server_addr->sin_port = htons(port);
    server_addr->sin_family = AF_INET;

    // create DNS query message
    char message[] = "Hello, server!"; //TODO: change this to real message

    // send socket to server
    sendto(sock, message, strlen(message), 0,
           (const struct sockaddr*)server_addr, sizeof(*server_addr));

    // wait for server response
    char buf[UDP_MSG_SIZE];
    socklen_t server_addr_len = sizeof(*server_addr);
    ssize_t recv_size = recvfrom(sock, buf, UDP_MSG_SIZE - 1, 0,
                                 (struct sockaddr*)server_addr, &server_addr_len);
    if (recv_size == -1) {
        fprintf(stderr, "data receiving failed\n");
        exit(EXIT_FAILURE);
    }

    buf[UDP_MSG_SIZE] = '\0';
    printf("message received from server:\n%s", buf);

    /*
     * NAME
     * TYPE
     * CLASS
     * TTL
     * RDLENGTH
     * RDATA
     *
     * TYPE - 1  : A
     *      - 5  : CNAME
     *      - 28 : AAAA
     *
     * CLASS - 1 : IN
     *
     *
     * */

//    printf("%s\n%s\n", server, address);

    close(sock);
    freeaddrinfo(result);

    free(server);
    free(address);
    return 0;
}
