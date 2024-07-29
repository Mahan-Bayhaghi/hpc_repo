# sudo apt install libpcap-dev libjansson-dev

CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lpcap -ljansson -lpthread
TARGET = hpc_teamID

all: $(TARGET)

$(TARGET): hpc_teamID.o
	$(CC) -o $(TARGET) hpc_teamID.o $(LDFLAGS)

hpc_teamID.o: hpc_teamID.c
	$(CC) $(CFLAGS) -c hpc_teamID.c

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
