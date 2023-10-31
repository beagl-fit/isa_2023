all: dns

dns: dns.c
	gcc -std=gnu99 -Wall -Wextra -o dns dns.c

clean:
	rm -f dns

test: dns
	bash test.sh

.PHONY: all clean
