gcc -Wall -O2 hpc_teamID_static.c -o a.o  -lpcap -ljansson -lpthread
./a.o ../low_testcase/snake_pattern.pcap
