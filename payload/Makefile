CC=gcc
CFLAGS=--static-pie -flto -T ./static-pie.ld -Os
LDFLAGS=-T ./static-pie.ld


build:
	$(CC) $(CFLAGS) -o main ./main.c
	strip main
