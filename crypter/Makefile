.PHONY: all clean runtest

CC = cc
CFLAGS = -Wall
OUTPUT = output

all: encrypt decrypt runtest

clean:
	rm -f crypto.o encrypt decrypt test.o test run.o

crypto.o: crypto.c
	$(CC) $(CFLAGS) -c crypto.c

run.o: run.c
	$(CC) $(CFLAGS) -c run.c

encrypt: run.o crypto.o
	$(CC) -o encrypt run.o crypto.o

decrypt: run.o crypto.o
	$(CC) -o decrypt run.o crypto.o

runtest: test.o crypto.o
	$(CC) -o test test.o crypto.o

test.o: test.c
	$(CC) $(CFLAGS) -c test.c
