CC = g++
CFLAGS = -g -Wall

all: hw4

.cpp.o:
	$(CC) $(CFLAGS) -c $< -lcapstone

hw4: hw4_elf.o hw4.o
	$(CC) $(CFLAGS) -o $@ $^ -lcapstone

.PHONY: clean

clean:
	rm *.o hw4