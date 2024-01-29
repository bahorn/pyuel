CFLAGS=--static-pie -flto -T ./static-pie.ld  -O0 -g
LDFLAGS=-T ./static-pie.ld

build:
	gcc $(CFLAGS) -o main ./main.c
	strip main
