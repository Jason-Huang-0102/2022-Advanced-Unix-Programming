CC = gcc
ASSEM = yasm
AFLAGS = -f elf64 -DYASM -D__x86_64__ -DPIC
CFLAGS = -c -g -Wall -fno-stack-protector

.PHONY: clean test

all: libmini.so start.o

start.o: start.asm
	$(ASSEM) $(AFLAGS) start.asm -o start.o

libmini.so: libmini64.asm libmini.c
	$(ASSEM) $(AFLAGS) libmini64.asm -o libmini64.o
	$(CC) $(CFLAGS) -fPIC -nostdlib libmini.c
	ld -shared -o libmini.so libmini64.o libmini.o

test: start.o test.c
	$(CC) $(CFLAGS) -nostdlib -I. -I.. -DUSEMINI test.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o test test.o start.o -L. -L.. -lmini

write1: start.o write1.c
	$(CC) $(CFLAGS) -nostdlib -I. -I.. -DUSEMINI write1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o write1 write1.o start.o -L. -L.. -lmini

alarm1: start.o alarm1.c
	$(CC) $(CFLAGS) -nostdlib -I. -I.. -DUSEMINI alarm1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm1 alarm1.o start.o -L. -L.. -lmini

alarm2: start.o alarm2.c
	$(CC) $(CFLAGS) -nostdlib -I. -I.. -DUSEMINI alarm2.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm2 alarm2.o start.o -L. -L.. -lmini
	rm alarm2.o

alarm3: start.o alarm3.c
	$(CC) $(CFLAGS) -nostdlib -I. -I.. -DUSEMINI alarm3.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm3 alarm3.o start.o -L. -L.. -lmini
	rm alarm3.o
jmp1: start.o jmp1.c	
	$(CC) $(CFLAGS) -nostdlib -I. -I.. -DUSEMINI jmp1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o jmp1 jmp1.o start.o -L. -L.. -lmini
	rm jmp1.o
clean:
	rm -f a.out test *.o libmini.so