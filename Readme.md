# ISA 2023 - DNS resolver
DNS resolver that can send **A**, **AAAA** or **PTR** queries to a server 
and knows how to interpret **A**, **AAAA** and **CNAME** types of resource records.

### Usage:
**./dns [-r] [-x] [-6] -s server [-p port] address**

**-s server** and **address** are required arguments

* **-r** : for recursive search
* **-x** : for reverse query (answer will not be interpreted)
* **-6** : desire _AAAA_ (IPv6) record instead of _A_ (IPv4) record
* **-s server** : DNS server where the query will be sent (IP or hostname)
* **-s port** : port of DNS server where the query will be sent (default _53_)
* **address** : queried name or IP (_-x_)

### Make
* **make** - creates dns executable file
* **make clean** - removes dns executable file
* **make test** - creates dns executable file and runs shell script containing tests

#### Libraries
_regex.h_ library is used, therefore _-lregex_ is used

_netdb.h_ library is used, therefore _-lresolv_ was used expected to be required, however, 
after its inclusion make failed on **Eva**

### Testing
Testing done on Fedora 37 and Eva school server.
* **Valgrind** : didn't find any memory leaks
* **Manual tests** : dns can send and interpret required types of queries 
* **Automated tests** : (_test.sh_) all tests passed on Fedora, last fails on Eva
  * _getaddrinfo()_ doesn't fail when asked about **some.completely.unknown.and.non-existent.server.cz**
