CFLAGS=-static -O0
LDFLAGS=-T ./static-pie.ld

build:
	$(CC) $(CFLAGS) -c ./main.c
	$(LD) $(LDFLAGS) ./main.o -o main
	strip main
