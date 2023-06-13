CC=gcc
CFLAGS=-c

hook: hook.s
	$(CC) $(CFLAGS)  $^ -o hook.o

asm_hooked: t.c
	$(CC) hook.o t.c -o asm_hooked

all: hook asm_hooked

clean:
	rm -f *.o asm_hooked
