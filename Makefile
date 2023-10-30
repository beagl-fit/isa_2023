CC = gcc
CFLAGS = -std=C99 -Wall -Wextra

EXEC = main

SRC = $(EXEC).c

OBJ = $(SRC:.c=.o)

LIBS = -lregex -lresolv

all: $(EXEC)

$(EXEC):$(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(EXEC)

test: $(EXEC)
	./test

.PHONY: all clean