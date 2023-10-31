all: dns

dns: dns.c
	gcc -o dns dns.c

clean:
	rm -f dns

test: dns
	bash test.sh

.PHONY: all clean
