# sudo apt install libpcap-dev libjansson-dev

CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lpcap -ljansson -lpthread
TARGET = hpc_teamID

all: $(TARGET)

$(TARGET): hpc_teamID_mercator.o
	$(CC) -o $(TARGET) hpc_teamID_mercator.o $(LDFLAGS)

hpc_teamID.o: hpc_teamID_mercator.c
	$(CC) $(CFLAGS) -c hpc_teamID_mercator.c

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
