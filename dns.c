// Author   : David Novak (xnovak2r)
// Date     : Oct 2023
// Subject  : ISA
// Project  : DNS resolver

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <regex.h>
#include <getopt.h>
#include <netinet/in.h>

/*
 * TYPE - 1  : A
 *      - 5  : CNAME
 *      - 28 : AAAA
 *      - 12 : PTR
 *
 * CLASS - 1 : IN
 * */

/// types
#define A 1     // ipv4
#define AAAA 28 // ipv6
#define CNAME 5 // canonical name
#define PTR 12  // reverse query

#define ID 255  /// any 16-bit number
#define IN 1    /// class

#define UDP_PORT 53
#define UDP_MSG_SIZE 512

#define PORT_MIN 0
#define PORT_MAX 65353

#define MAX_DOMAIN_LENGTH 63
#define MAX_HOSTNAME_LENGTH 255

#define IPv4 0
#define IPv6 1
#define HOSTNAME 2

#define IPv4_REGEX_PATTERN "^(0|[1-9][0-9]{0,2})\\.(0|[1-9][0-9]{0,2})\\.(0|[1-9][0-9]{0,2})\\.(0|[1-9][0-9]{0,2})$"

///global variables for cleanup function
struct sockaddr_in *s_in = NULL;
struct sockaddr_in6 *s_in6 = NULL;
char *global_server = NULL, *prt = NULL, *a = NULL, *sa = NULL, *a2 = NULL;
int sk = -1;
struct addrinfo *r = NULL;

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
    /* Function strips hostname of HTTP(S) and WWW parts as well as the . at the end.
     * It returns length of the hostname that might be used for checks
     * */
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

    for (int i = 0; (size_t)i < length - dot; ++i) {
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
    /* Function figures if server was given in IPv4/IPv6/hostname format.
     * Uses regex for IPv4 and tries to find ':' for IPv6
     * returns: 0 - IPv4
     *          1 - IPv6
     *          2 - Hostname
     *         -1 - Error
     */
    regex_t ipv4;
    int res;
    res = regcomp(&ipv4, IPv4_REGEX_PATTERN, REG_EXTENDED);
    if (res != 0) {
        fprintf(stderr, "Compiling of regex failed\n");
        return -1;
    }

    res = regexec(&ipv4, srv, 0, NULL, 0);
    regfree(&ipv4);
    if (res == 0)
        return IPv4;

    res = 0;
    strip_name(&srv);
    while (*srv) {
        if (*srv == ':' && res < 5)
            return IPv6;
        else if (res >= 5)
            break;
        srv++;
        res++;
    }
    return HOSTNAME;
}


void fill_question(struct DNS_Question *q, int type) {
    /* Function fills information to struct DNS_Question, it used to have the name field as well, but that has been
     * removed due to problems caused by differing sizes of that field
     * */
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
    /* Helper function used by convert name, since C doesn't have any array.append function that auto enlarges the array
     * */
    (*size)++;
    *array = realloc(*array, *size * sizeof(int));
}

int convert_name(char **name) {
    /*  Function converts the address given by user to the corresponding address in DNS format
     * */
    int *dot_indexes_array = NULL, array_size = 0;
    unsigned long size = strip_name(*&name);
    if (size == 0 || size > MAX_HOSTNAME_LENGTH)
        return -1;

    /// find all '.' and save their position to an array
    for (int i = 0; (size_t)i < size; ++i) {
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

    /// replaces all the '.' in address with number of bytes of the following domain
    for (int i = 0; i < array_size; ++i) {
        if (i + 1 < array_size && dot_indexes_array[i + 1] - dot_indexes_array[i] > MAX_DOMAIN_LENGTH) {
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

    /// creates a new string that has space for the number of bytes of the first domain
    char *new_name = malloc(size + 2);
    if (new_name == NULL) {
        free(dot_indexes_array);
        return -1;
    }

    /// set first letter of string to NoB and second to \0 for strcat to function properly
    new_name[0] = (size_t) dot_indexes_array[0];
    new_name[1] = '\0';

    /// append the name to new string and save it back to the first one so that it is usable in main
    strcat(new_name, *name);
    *name = strdup(new_name);
    if (*name == NULL) {
        free(dot_indexes_array);
        free(new_name);
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    a2 = *name;

    free(new_name);
    free(dot_indexes_array);
    return 0;
}


int parse_header(char *msg, bool rev_query, char **print_ptr, int *an_cnt) {
    /* Function parses header of DNS query message with use of the struct DNS_HEADER.
     * It checks ID and flags, prepares a string that will be printed later and returns ERROR code
     * */
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

    an_cnt[0] = ntohs(h.ANCOUNT);
    an_cnt[1] = ntohs(h.NSCOUNT);
    an_cnt[2] = ntohs(h.ARCOUNT);

    *print_ptr = strdup(print);
    check = 0b1111 & flags;
    return check;
}


/*
                              1  1  1  1  1  1
0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                                               /
/                      NAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
void print_data(char *msg, char *type, ssize_t *size) {
    /* Function prints out the RDATA portion of the RR
     * */
    uint16_t RDLENGTH, data6;
    uint8_t data;

    memcpy(&RDLENGTH, msg, sizeof(uint16_t ));
    RDLENGTH = ntohs(RDLENGTH);

    if (strcmp(type, "A") == 0) {
        /// if data are of type A, print out the IPv4
        for (uint16_t i = 1; i < RDLENGTH; i++) {
            memcpy(&data, msg + i + 1, sizeof(uint8_t ));
            printf("%u.", data);
        }
        memcpy(&data, msg + RDLENGTH + 1, sizeof(uint8_t ));
        printf("%u\n", data);
    } else if (strcmp(type, "AAAA") == 0) {
        /// if data are of type AAAA, print out the IPv6
        for (uint16_t i = 1; i < RDLENGTH; i++) {
            memcpy(&data6, msg + i + 1, sizeof(uint16_t ));
            printf("%04X:", data6);
        }
        memcpy(&data6, msg + RDLENGTH + 1, sizeof(uint16_t ));
        printf("%04X\n", data6);
    } else {
        /// otherwise the data are of type CNAME, so print out the canonical name
        for (uint16_t i = 1; i < RDLENGTH; ++i) {
            char c = msg[i + 2];
            if (c < MAX_DOMAIN_LENGTH)
                c = '.';
            printf("%c", c);
        }
        printf("\n");
    }
    *size -= RDLENGTH * sizeof(uint8_t) + sizeof(uint16_t);
    memmove(msg, msg + RDLENGTH * sizeof(uint8_t) + sizeof(uint16_t), *size);
}


void parse_RR_and_Print(char *msg, ssize_t *size, const char *whole_msg) {
    /* Function parses resource record part of DNS query message and prints out result
     * */
    uint16_t name;
    unsigned int ptr;
    struct DNS_Question q2;
    int32_t ttl;
    char *type;

    /// check if there will be a name or a pointer in name
    memcpy(&name, msg, sizeof(uint16_t));
    name = ntohs(name);
    uint16_t check = 0b11 << 14 & name;
    if (check == 0b11 << 14) {
        /// if it is a pointer, the size of name will be 2 * uint16 starting with 11 followed by pointer to name
        memcpy(&q2, msg + sizeof(uint16_t), sizeof(struct DNS_Question));
        if (ntohs(q2.QTYPE) == A)
            type = "A";
        else if (ntohs(q2.QTYPE) == AAAA)
            type = "AAAA";
        else if (ntohs(q2.QTYPE) == CNAME)
            type = "CNAME";
        else {
            fprintf(stderr, "Got response with an unknown QTYPE\n");
            return;
        }
        memcpy(&ttl, msg + sizeof(uint16_t) + sizeof(struct DNS_Question), sizeof(int32_t ));

        ptr = name & 0b0011111111111111;
        for (int i = 1; whole_msg[i + ptr] != '\0'; ++i) {
            char c = whole_msg[i + ptr];
            if (c <= MAX_DOMAIN_LENGTH)
                c = '.';
            printf("%c", c);
        }
        printf("., %s, IN, %d, ", type, ntohl(ttl));
        *size -= 2 * sizeof(uint16_t) + sizeof(struct DNS_Question) + sizeof(int32_t);
        memmove(msg, msg + sizeof(uint16_t) + sizeof(struct DNS_Question) + sizeof(int32_t ), *size);
        print_data(msg, type, size);

    } else {
        /// if it is a name, just print it out (unless the type is wrong) and the other parts of RR follow right after
        ptr = 0;
        while (msg[ptr] != '\0')
            ptr++;

        memcpy(&q2, msg + ptr + 1, sizeof(struct DNS_Question));
        if (ntohs(q2.QTYPE) == A)
            type = "A";
        else if (ntohs(q2.QTYPE) == AAAA)
            type = "AAAA";
        else if (ntohs(q2.QTYPE) == CNAME)
            type = "CNAME";
        else {
            fprintf(stderr, "Got response with an unknown QTYPE\n");
            return;
        }

        for (unsigned int i = 1; i < ptr; ++i) {
            char c = msg[i];
            if (c <= MAX_DOMAIN_LENGTH)
                c = '.';
            printf("%c", c);
        }
        *size -= (ptr + 1) * sizeof(uint8_t ) + sizeof(struct DNS_Question);
        memmove(msg, msg + ptr + 1 + sizeof(struct DNS_Question), *size);

        memcpy(&ttl, msg, sizeof(int32_t ));
        printf("., %s, IN, %d, ", type, ntohl(ttl));

        *size -= sizeof(uint32_t );

        memmove(msg, msg + sizeof(uint32_t), *size);
        print_data(msg, type, size);
    }
}


void check_length(char *hostname) {
    /* Function checks if the length of hostname and number of domains are ok
     * */
    size_t dom_start = 0, dom_end = 0;
    if (strlen(hostname) > MAX_HOSTNAME_LENGTH) {
        fprintf(stderr, "Hostname is too long\n");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < strlen(hostname); ++i) {
        if (hostname[i] == '.') {
            dom_end = i;
            if (dom_end - dom_start - 1 > MAX_DOMAIN_LENGTH)  {
                fprintf(stderr, "Domain in server hostname too long\n");
                exit(EXIT_FAILURE);
            }
            dom_start = dom_end;
        }
    }
}


void cleanup(){
    /* cleanup function (called when exiting program)
     * */
    if (s_in != NULL)
        free(s_in);

    if (s_in6 != NULL)
        free(s_in6);

    if (global_server != NULL)
        free(global_server);

    if (a != NULL)
        free(a);

    if (prt != NULL)
        free(prt);

    if (sk != -1)
        close(sk);

    if (r != NULL)
        freeaddrinfo(r);

    if (sa != NULL)
        free(sa);

    if (a2 != NULL)
        free(a2);
}

/******************************************/
/******************************************/
/*********  MAIN STARTS HERE  *************/
/******************************************/
/******************************************/

int main(int argc, char **argv) {
    char *server, *address, *print_ART, *saved_address;
    int opt, type = A, port = UDP_PORT, sock = -1, addr_info, name_conv;
    bool rec_desired = false, rev_query = false, addr = false, srv = false;
    ssize_t recv_size;
    struct addrinfo hints;
    struct addrinfo *result;
    struct DNS_Header header;
    struct DNS_Question question;
    struct timeval timeout;
    struct sockaddr_in *server_addr  = malloc(sizeof(struct sockaddr_in));
    struct sockaddr_in6 *server_addr6 = malloc(sizeof(struct sockaddr_in6));

    s_in = server_addr;
    s_in6 = server_addr6;

    atexit(cleanup);

    if (server_addr == NULL || server_addr6 == NULL) {
        fprintf(stderr, "Allocation of space for struct sockaddr_in(6) failed\n");
        exit(EXIT_FAILURE);
    }

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
                if (srv) {
                    fprintf(stderr, "Got more than 1 server\n");
                    fprintf(stderr, "Usage: %s [-r] [-x] [-6] -s server [-p port] address\n", argv[0]);
                    exit(EXIT_FAILURE);
                }

                srv = true;
                server = strdup(optarg);
                if (server == NULL) {
                    fprintf(stderr, "Memory allocation for 'server' failed\n");
                    exit(EXIT_FAILURE);
                }
                global_server = server;
                break;

            case 'p':
                if (1 == 1) {
                    ;
                }
                char *end;
                long p = strtol(optarg, &end, 10);
                if (*end != '\0') {
                    fprintf(stderr, "'port' is not a number\n");
                    fprintf(stderr, "Usage: %s [-r] [-x] [-6] -s server [-p port] address\n", argv[0]);
                    exit(EXIT_FAILURE);
                }
                if (p < PORT_MIN || p > PORT_MAX) {
                    fprintf(stderr, "Invalid port number\n");
                    fprintf(stderr, "Usage: %s [-r] [-x] [-6] -s server [-p port] address\n", argv[0]);
                    exit(EXIT_FAILURE);
                }
                port = (int)p;
                break;

            case '?':
                fprintf(stderr, "Usage: %s [-r] [-x] [-6] -s server [-p port] address\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        addr = true;
        address = strdup(argv[optind]);
        if (address == NULL) {
            fprintf(stderr, "Memory allocation for 'address' failed\n");
            exit(EXIT_FAILURE);
        }
        a = address;
    }
    if (optind + 1 < argc) {
        fprintf(stderr, "Got more than 1 address\n");
        fprintf(stderr, "Usage: %s [-r] [-x] [-6] -s server [-p port] address\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /// check for requred arguments ///
    if (!addr || !srv) {
        fprintf(stderr, "'-s server' and 'address' are required\n");
        fprintf(stderr, "Usage: %s [-r] [-x] [-6] -s server [-p port] address\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    fill_header(&header, rev_query, rec_desired);

    /// check what type of query is asked for ///
    if (rev_query) {
        /// if reversed query is required the given ip to DNS form
        int form = format(address);
        if (form == IPv4) {
            int ip[4], ip_size = 0;
            for (int i = 0; i < 4; ++i) {
                int dot = 0;
                while (address[ip_size + dot] != '.' && address[ip_size + dot] != '\0')
                    dot++;
                char ip_str[] = {'\0', '\0','\0','\0'};
                strncpy(ip_str, address + ip_size, dot);
                ip[i] = atoi(ip_str);
                ip_size += dot + 1;
            }

            address = realloc(address, (strlen(address) + strlen(".in-addr.arpa")) * sizeof(char));
            if (address == NULL) {
                fprintf(stderr, "Reallocation of space for 'address' failed\n");
                exit(EXIT_FAILURE);
            }
            sprintf(address, "%d.%d.%d.%d\x0Cin-addr.arpa", ip[3], ip[2], ip[1], ip[0]);
        } else if (form == IPv6) {
            address = realloc(address, (strlen(address) + strlen(".in6.arpa")) * sizeof(char));
            if (address == NULL) {
                fprintf(stderr, "Reallocation of space for 'address' failed\n");
                exit(EXIT_FAILURE);
            }

            int column[7], position = 0, col_pos = 0;
            while((size_t)position < strlen(address)) {
                if (address[position] == ':' && col_pos < 7) {
                    column[col_pos] = position;
                    col_pos++;
                } else if (col_pos == 7) {
                    fprintf(stderr, "Invalid for of IPv6 'address'\n");
                    exit(EXIT_FAILURE);
                }
                position++;
            }

            char DNS_form_IPv6[strlen(address)], *strtok_part;
            DNS_form_IPv6[0] = '\0';

            position = 0;

            strtok_part = strtok(address, ":");
            while (strtok_part != NULL) {
                unsigned long patr_length = strlen(strtok_part);
                char part[] = {'\0', '\0', '\0', '\0', '\0'};
                for (size_t i = 0; i < patr_length; ++i) {
                    part[i] = strtok_part[patr_length - i - 1];
                }

                strcat(DNS_form_IPv6, part);
                strtok_part = strtok(NULL, ":");

                if (position < col_pos) {
                    strcat(DNS_form_IPv6, ".");
                }
                position++;
                if (column[position] - column[position - 1] == 1 && position < col_pos) {
                    strcat(DNS_form_IPv6, ".");
                    position++;
                }
            }
            sprintf(address, "%s\x08in6.arpa", DNS_form_IPv6);
        } else {
            fprintf(stderr, "Wrong format of address for the reversed query\n");
            exit(EXIT_FAILURE);
        }

        saved_address = strdup(address);
        if (saved_address == NULL) {
            fprintf(stderr, "Memory allocation for string duplication failed\n");
            exit(EXIT_FAILURE);
        }
        sa = saved_address;

        type = PTR;

    } else {
        /// otherwise convert domain name to DNS format
        check_length(address);
        saved_address = strdup(address);
        if (saved_address == NULL) {
            fprintf(stderr, "Memory allocation for string duplication failed\n");
            exit(EXIT_FAILURE);
        }
        sa = saved_address;

        name_conv = convert_name(&address);
        if (name_conv == -1) {
            fprintf(stderr, "Invalid domain name\n");
            exit(EXIT_FAILURE);
        } else if (name_conv == -2) {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
    }

    fill_question(&question, type);

    /// check if server was given as an IP or hostname ///
    int f = format(server);
    if (f == -1)
        exit(EXIT_FAILURE);

    if (f == HOSTNAME) {
        check_length(server);
        /// get server IP address from server name  ///
        // from: https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
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
        r = result;
        /*----------------------------------------------------------------------------------*/
    }

    /// create socket ///
    if (f == IPv6) {
        sock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sock < 0) {
            fprintf(stderr, "Creation of socket failed\n");
            exit(EXIT_FAILURE);
        }
    } else {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            fprintf(stderr, "Creation of socket failed\n");
            exit(EXIT_FAILURE);
        }
    }
    sk = sock;

    /// set server info ///
    if (f == IPv6) {
        if (inet_pton(AF_INET6, server, &server_addr6->sin6_addr) <= 0) {
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
    // from: https://stackoverflow.com/questions/4181784/how-to-set-socket-timeout-in-c-when-making-multiple-connections
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0){
        fprintf(stderr, "Setting timeout to socket failed\n");
        exit(EXIT_FAILURE);
    }

    /// create DNS query message ///
    uint8_t buffer[sizeof(struct DNS_Header) + strlen(address) + 1 + 2 * sizeof(uint16_t)];
    memcpy(buffer, &header, sizeof(struct DNS_Header));
    if (rev_query) {
        memcpy(buffer + sizeof(struct DNS_Header), address, strlen(address));
        memcpy(buffer + sizeof(struct DNS_Header) + strlen(address), &question,
                sizeof(struct DNS_Question));
        buffer[sizeof(buffer) - 1] = '\0';
    } else {
        memcpy(buffer + sizeof(struct DNS_Header), address, strlen(address) + 1);
        memcpy(buffer + sizeof(struct DNS_Header) + strlen(address) + 1, &question,
                sizeof(struct DNS_Question));
    }

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
    } else {
        socklen_t server_addr_len = sizeof(*server_addr);
        recv_size = recvfrom(sock, buf, UDP_MSG_SIZE - 1, 0,
                             (struct sockaddr*)server_addr, &server_addr_len);
    }
    if (recv_size == -1) {
        fprintf(stderr, "data receiving failed\n");
        exit(EXIT_FAILURE);
    }
    char buf_cpy[recv_size];
    memcpy(&buf_cpy, buf, recv_size);

    /// parse header of received message ///
    int an_cnt[3];
    int parse_result = parse_header(buf, rev_query, &print_ART, an_cnt);
    prt = print_ART;
    // Error definitions directly from RFC 1035
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

    /// print out requested info about question ///
    printf("%s", print_ART);
    char *print_type;
    if (type == A)
        print_type = "A";
    else if (type == AAAA)
        print_type = "AAAA";
    else
        print_type = "PTR";

    printf("\nQuestion Section (1)\n%s, %s, IN\nAnswer Section(%d)\n", saved_address, print_type, an_cnt[0]);

    /// move message to the beginning of the first resource record ///
    ssize_t size = recv_size;
    size -= sizeof(struct DNS_Header) - 1;
    memmove(buf, buf + sizeof(struct DNS_Header), size);
    size -= strlen(address) + sizeof(struct DNS_Question);
    memmove(buf, buf + (size_t )strlen(address) + 1 + sizeof(struct DNS_Question), size);

    /// parse and print out all of the RRs into their respective sections
    for (int i = 0; i < an_cnt[0]; ++i)
        parse_RR_and_Print(buf, &size,buf_cpy);

    printf("Authority Section(%d)\n", an_cnt[1]);
    for (int i = 0; i < an_cnt[1]; ++i)
        parse_RR_and_Print(buf, &size,buf_cpy);

    printf("Additional Section(%d)\n", an_cnt[2]);
    for (int i = 0; i < an_cnt[2]; ++i)
        parse_RR_and_Print(buf, &size,buf_cpy);

    return 0;
}
