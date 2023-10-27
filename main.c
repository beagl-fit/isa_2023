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

#define MAX_DOMAIN_LENGTH 63
#define MAX_HOSTNAME_LENGTH 255

#define IPv4_regex "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"

#define IPv4 0
#define IPv6 1
#define HOSTNAME 2

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

struct DNS_Question {
    uint16_t QTYPE;
    uint16_t QCLASS;
};

//struct DNS_Message {
//    struct DNS_Header header;
//    struct DNS_Question question;
//} __attribute__((packed));

unsigned long strip_name(char **name) {
    unsigned long length = strlen(*name);
    int dot;

    if(strncmp("http://www.", *name, strlen("http://www.")) == 0) {
        dot = strlen("http://www.");
    } else if (strncmp("https://www.", *name, strlen("https://www.")) == 0) {
        dot = strlen("https://www.");
    } else if (strncmp("www.", *name, strlen("www.")) == 0) {
        dot = strlen("www.");
    } else {
        if ((*name)[length - 1] == '.'){
            (*name)[length - 1] = '\0';
            length --;
        }
        return length;
    }

    for (int i = 0; i < length - dot; ++i) {
        (*name)[i] = (*name)[i + dot];
    }
    (*name)[length - dot] = '\0';
    length = strlen(*name);
    if ((*name)[length - 1] == '.'){
        (*name)[length - 1] = '\0';
        length--;
    }
    return length;
}

int format(char *srv) {
    /* function figures if server was given in IPv4/IPv6/hostname format
     * returns: 0  - IPv4
     *          1  - IPv6
     *          2  - Hostname
     *          -1 - Error
     */
    regex_t ipv4;
    int res;

    res = regcomp(&ipv4, IPv4_regex, REG_EXTENDED);
    if (res != 0) {
        fprintf(stderr, "Compiling of regex failed\n");
        return -1;
    }

    res = regexec(&ipv4, srv, 0, NULL, 0);
    regfree(&ipv4);
    if (res == 0)
        return IPv4;

    strip_name(&srv);
    while (*srv) {
        if (*srv == ':')
            return IPv6;
        srv++;
    }

    return HOSTNAME;
}

void fill_question(struct DNS_Question *q, int type) {
    q->QTYPE = htons(type);
    q->QCLASS = htons(IN);
}

void fill_header(struct DNS_Header *h, bool rev_query, bool rec_desired) {
    /* function fills information to DNS header
     * */
    uint16_t flags = 0b0;
    if (rev_query) {
        flags += 0b1 << 11;
    }

    if (rec_desired) {
        flags += 0b1 << 8;
    }

    h->id = htons(ID);
    h->flags = htons(flags);
    h->QDCOUNT = htons(1);
    h->ANCOUNT = 0;
    h->NSCOUNT = 0;
    h->ARCOUNT = 0;
}

void increment_array_size(int **array, int *size) {
    (*size)++;
    *array = realloc(*array, *size * sizeof(int));
}

int convert_name(char **name) {
    /*  Converts the address given to address in DNS format
     * */
    int *dot_indexes_array = NULL, array_size = 0;
    unsigned long size = strip_name(*&name);
    if (size == 0 || size > MAX_HOSTNAME_LENGTH)
        return -1;

    // find all '.' and save their position to an array
    for (int i = 0; i < size; ++i) {
        if ((*name)[i] == '.') {
            increment_array_size(&dot_indexes_array, &array_size);
            if (dot_indexes_array == NULL)
                return -2;

            dot_indexes_array[array_size - 1] = i;
        }
    }
    if (array_size < 1) {
        free(dot_indexes_array);
        return -1;
    }

    // replaces all the '.' in address with number of bytes of the following domain
    for (int i = 0; i < array_size; ++i) {
        if (dot_indexes_array[i + 1] - dot_indexes_array[i] > MAX_DOMAIN_LENGTH) {
            free(dot_indexes_array);
            return -1;
        }
        int next_index = dot_indexes_array[i];
        size_t s;

        if (i == array_size - 1)
            s = (size - next_index - 1);
        else
            s = (dot_indexes_array[i + 1] - next_index - 1);

        (*name)[next_index] = s;
    }

    // adds number of bytes of the first domain to the beginning of address
    char *new_name = malloc(size + 2);
    if (new_name == NULL) {
        free(dot_indexes_array);
        return -1;
    }

    new_name[0] = (size_t) dot_indexes_array[0];
    strcat(new_name, *name);
    *name = strdup(new_name);

    free(new_name);
    free(dot_indexes_array);
    return 0;
}

// TODO: remove this function
void print_buffer(unsigned char *buffer) {
    for (int i = 0; i < 45; ++i) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}

int parse_header(char *msg, bool rev_query, char **print_ptr, int *an_cnt) {
    struct DNS_Header h;
    memcpy(&h, msg, sizeof(struct DNS_Header));
    if(ntohs(h.id) != ID)
        return -1;

//    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//      0   0000      0   0   0   0   000     0000
//     15   14-11     10  9   8   7   6-4     3-0
    uint16_t flags = ntohs(h.flags), check;
    check = 0b1 << 15 & flags;
    if (check != 0b1 << 15)
        return -2;

    check = 0b1111 << 11 & flags;
    if (!((check == 0b0 && !rev_query) || (check == 0b1 << 11 && rev_query)))
        return -2;

    char print[strlen("Authoritative: Yes, Recursive: Yes, Truncated: Yes") + 1];

    check = 0b1 << 10 & flags;
    if (check == 0b0)
        strcpy(print, "Authoritative: No, ");
    else
        strcpy(print, "Authoritative: Yes, ");

    check = 0b1 << 7 & flags;
    if (check == 0b0)
        strcat(print, "Recursive: No, ");
    else
        strcat(print, "Recursive: Yes, ");

    check = 0b1 << 9 & flags;
    if (check == 0b0)
        strcat(print, "Truncated: No");
    else
        strcat(print, "Truncated: Yes");

    *an_cnt = ntohs(h.ANCOUNT);

    *print_ptr = strdup(print);
    check = 0b1111 & flags;
    return check;
}
void print_data(char *msg, char *type) {
    uint16_t RDLENGTH;
    uint8_t data;

    memcpy(&RDLENGTH, msg + sizeof(uint16_t) + sizeof(struct DNS_Question) + sizeof(int32_t ),
            sizeof(uint16_t ));
    RDLENGTH = ntohs(RDLENGTH);
//    printf("\n LENGHT: %u\n", RDLENGTH);

    if (strcmp(type, "A") == 0) {
        for (uint16_t i = 1; i < RDLENGTH; i++) {
            memcpy(&data, msg + sizeof(uint16_t) + sizeof(struct DNS_Question) + sizeof(int32_t ) + i + 1,
                   sizeof(uint8_t ));
            printf("%u.", data);
        }
        memcpy(&data, msg + sizeof(uint16_t) + sizeof(struct DNS_Question) + sizeof(int32_t ) + RDLENGTH + 1,
               sizeof(uint8_t ));
        printf("%u\n", data);

    } else if (strcmp(type, "AAAA") == 0) {
        printf("IPv6\n");
    } else {    //CNAME
        printf("CNAME\n");
    }
}

void parse_message(char *msg, char *addr, ssize_t size, char **saved_addr) {
    memmove(msg, msg + sizeof(struct DNS_Header), size - sizeof(struct DNS_Header) + 1);
    struct DNS_Question q;
    memcpy(&q, msg + (size_t )strlen(addr) + 1, sizeof(struct DNS_Question));
    memmove(msg, msg + (size_t )strlen(addr) + 1 + 2 * sizeof(uint16_t),
            size - sizeof(struct DNS_Header) + 1 - (size_t )strlen(addr) - 3); //TODO: check the third agr

    uint16_t name;
    int ptr;
    memcpy(&name, msg, sizeof(uint16_t));
    name = ntohs(name);
    uint16_t check = 0b11 << 14 & name;
    if (check == 0b11 << 14) {
        ptr = name & 0b0011111111111111;
        if (ptr == 12) {
            struct DNS_Question q2;
            memcpy(&q2, msg + 2 * sizeof(uint16_t), sizeof(struct DNS_Question));
            char *type;
            if (ntohs(q2.QTYPE) == 1)
                type = "A";
            else if (ntohs(q2.QTYPE) == 5)
                type = "AAAA";
            else if (ntohs(q2.QTYPE) == 28)
                type = "CNAME";
            else
                exit(EXIT_FAILURE);
            strip_name(&*saved_addr);
            int32_t ttl;
            memcpy(&ttl, msg + sizeof(uint16_t) + sizeof(struct DNS_Question), sizeof(int32_t ));

            printf("%s, %s, IN, %d, ", *saved_addr, type, ntohl(ttl));
            print_data(msg, type);
        }
        else
            printf("\nptr != 12\n");

    } else {
        ;
        ;
        ;
    }
}









/// -lresolv in Makefile
int main(int argc, char **argv) {
    /// declaration of used variables ///
    char *server, *address, *print_ART, *saved_address;
    int opt, type = A, port = UDP_PORT, sock, addr_info, name_conv;//, server_format;
    bool rec_desired = false, rev_query = false, addr = false, srv = false;
    ssize_t recv_size;
    struct addrinfo hints, *result;
    struct sockaddr_in *server_addr;
    struct sockaddr_in6 *server_addr6;
    struct DNS_Header header;
    struct DNS_Question question;
    struct timeval timeout;

    /// argument handling ///
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

    /// check for requred arguments ///
    if (!addr || !srv) {
        fprintf(stderr, "'-s server' and 'address' are required\n");
        fprintf(stderr, "Usage: %s [-r] [-x] [-6] -s server [-p port] address\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    fill_header(&header, rev_query, rec_desired);
    saved_address = strdup(address);
    name_conv = convert_name(&address);
    if (name_conv == -1) {
        fprintf(stderr, "Invalid domain name\n");
        exit(EXIT_FAILURE);
    }else if (name_conv == -2) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    fill_question(&question, type);

    int f = format(server);
    if (f == -1)
        exit(EXIT_FAILURE);

    if (f == HOSTNAME) {
        /// get server IP address from server name  ///
        // https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
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
        /*----------------------------------------------------------------------------------*/
    }

    /// create socket ///
    AF_INET;AF_INET6;AF_UNSPEC;
    sock = socket(AF_INET, SOCK_DGRAM, 0); /// AF_INET for ipv4/AF_INET6 for ipv6/AF_UNSPEC for ipv4 or ipv6 ???
    if (sock < 0) {
        fprintf(stderr, "Creation of socket failed\n");
        exit(EXIT_FAILURE);
    }

    /// set server info ///
    if (f == IPv6) {
        if (inet_pton(AF_INET6, "2a01:430:120::4d5d:db6e", &(server_addr6->sin6_addr)) <= 0) {
            fprintf(stderr, "Error while converting server IP address\n");
            exit(EXIT_FAILURE);
        }
        server_addr6->sin6_family = AF_INET6;
        server_addr6->sin6_port = htons(port);
    } else {
        if (f == HOSTNAME) {
            server_addr = (struct sockaddr_in *) result->ai_addr;
        } else if (f == IPv4) {
            if (inet_pton(AF_INET, server, &server_addr->sin_addr) <= 0) {
                fprintf(stderr, "Error while converting server IP address\n");
                exit(EXIT_FAILURE);
            }
        }
        server_addr->sin_family = AF_INET;
        server_addr->sin_port = htons(port);
    }

    /// set a 30 sec timeout to socket for program not to wait indefinitely for a response ///
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0){
        fprintf(stderr, "Setting timeout to socket failed\n");
        exit(EXIT_FAILURE);
    }

    /// create DNS query message ///
    uint8_t buffer[sizeof(struct DNS_Header) + strlen(address) + 1 + 2 * sizeof(uint16_t)];
    memcpy(buffer, &header, sizeof(struct DNS_Header));
    memcpy(buffer + sizeof(struct DNS_Header), address, strlen(address) + 1);
    memcpy(buffer + sizeof(struct DNS_Header) + strlen(address) + 1, &question, sizeof(struct DNS_Question));

    /// send socket to server ///
    if (f == IPv6)
        sendto(sock, buffer, sizeof(buffer), 0,
               (const struct sockaddr*)server_addr6, sizeof(*server_addr6));
    else
        sendto(sock, buffer, sizeof(buffer), 0,
               (const struct sockaddr*)server_addr, sizeof(*server_addr));

    /// wait for response from server ///
    char buf[UDP_MSG_SIZE];
    if (f == IPv6) {
        socklen_t server_addr_len = sizeof(*server_addr6);
        recv_size = recvfrom(sock, buf, UDP_MSG_SIZE - 1, 0,
                             (struct sockaddr*)server_addr6, &server_addr_len);
        if (recv_size == -1) {
            fprintf(stderr, "data receiving failed\n");
            exit(EXIT_FAILURE);
        }
    } else {
        socklen_t server_addr_len = sizeof(*server_addr);
        recv_size = recvfrom(sock, buf, UDP_MSG_SIZE - 1, 0,
                             (struct sockaddr*)server_addr, &server_addr_len);
        if (recv_size == -1) {
            fprintf(stderr, "data receiving failed\n");
            exit(EXIT_FAILURE);
        }
    }

    buf[recv_size] = '\0';
    print_buffer(buf); //TODO: remove

    int an_cnt;
    int parse_result = parse_header(buf, rev_query, &print_ART, &an_cnt);
    switch (parse_result) {
        case 0:
            break;
        case -1:
            fprintf(stderr, "Received packet with different ID\n");
            exit(EXIT_FAILURE);
        case -2:
            fprintf(stderr, "Received packet with wrong flags\n");
            exit(EXIT_FAILURE);
        case 1:
            fprintf(stderr, "Format error - The name server was unable to interpret the query.\n");
            exit(EXIT_FAILURE);
        case 2:
            fprintf(stderr, "Server failure - The name server was unable to process this query due to a "
                            "problem with the name server.\n");
            exit(EXIT_FAILURE);
            break;
        case 3:
            fprintf(stderr, "Name Error - Meaningful only for responses from an authoritative nam server,"
                            " this code signifies that the domain name referenced in the query does not exist.\n");
            exit(EXIT_FAILURE);
        case 4:
            fprintf(stderr, "Not Implemented - The name server does not support "
                            "the requested kind of query.\n");
            exit(EXIT_FAILURE);
        case 5:
            fprintf(stderr, "Refused - The name server refuses to perform the specified operation for "
                            "policy reasons.  For example, a name server may not wish to provide the information to "
                            "the particular requester, or a name server may not wish to perform a particular operation"
                            " (e.g., zone transfer) for particular data.\n");
            exit(EXIT_FAILURE);
        default:
            fprintf(stderr, "Received unexpected error in DNS flags. Error code: %d\n", parse_result);
            exit(EXIT_FAILURE);
    }
    printf("SIZE:%zd\n\n", recv_size);

    printf("%s", print_ART);
    // TODO: check real type of record from received data, not "type"
    char *print_type;
    if (type == A)
        print_type = "A";
    else
        print_type = "AAAA";

    printf("\nQuestion Section (1)\n%s, %s, IN\nAnswer Section(%d)\n", saved_address, print_type, an_cnt);
    parse_message(buf, address, recv_size, &saved_address);

    /*
     * NAME     2
     * TYPE     1
     * CLASS    1
     * TTL      2
     * RDLENGTH 1
     * RDATA    RDLENGTH
     *
     * TYPE - 1  : A
     *      - 5  : CNAME
     *      - 28 : AAAA
     *
     * CLASS - 1 : IN
     *
     *
     * */

    close(sock);
    freeaddrinfo(result);

    free(print_ART);
    free(saved_address);
    free(server);
    free(address);
    return 0;
}
