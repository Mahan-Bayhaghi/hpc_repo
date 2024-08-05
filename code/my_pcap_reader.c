#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#pragma pack(push, 1)

typedef struct pcap_hdr_s {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

typedef struct ethernet_hdr_s {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} ethernet_hdr_t;

typedef struct ip_hdr_s {
    uint8_t  ihl:4, version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} ip_hdr_t;

typedef struct udp_hdr_s {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} udp_hdr_t;

#pragma pack(pop)

typedef struct udp_packet_s {
    uint32_t length;
    uint8_t *data;
    uint16_t id;
    uint8_t *payload;
    uint32_t payload_len;
} udp_packet_t;

udp_packet_t **udp_packets = NULL;
size_t udp_packet_count = 0;
size_t udp_packet_capacity = 0;
size_t last_read_index = 0;

int reading_done = 0;

pthread_mutex_t packet_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t packet_cond = PTHREAD_COND_INITIALIZER;

void add_udp_packet(const uint8_t *packet_data, uint32_t length) {
    pthread_mutex_lock(&packet_mutex);

    if (udp_packet_count == udp_packet_capacity) {
        printf("  - Reallocated total udp packet capacity from %ld to ", udp_packet_capacity);
        udp_packet_capacity = (udp_packet_capacity == 0) ? 1 : udp_packet_capacity * 2;  // double size of array each time it got full
        printf("%ld \n", udp_packet_capacity);
        udp_packets = (udp_packet_t **)realloc(udp_packets, udp_packet_capacity * sizeof(udp_packet_t *));
        if (!udp_packets) {
            perror("Unable to allocate memory for new udp packets array");
            exit(EXIT_FAILURE);
        }
    }

    udp_packets[udp_packet_count] = (udp_packet_t *)malloc(sizeof(udp_packet_t));
    if (!udp_packets[udp_packet_count]) {
        perror("Unable to allocate memory");
        exit(EXIT_FAILURE);
    }

    udp_packets[udp_packet_count]->length = length;
    udp_packets[udp_packet_count]->data = (uint8_t *)malloc(length);
    udp_packets[udp_packet_count]->id = 456;
    if (!udp_packets[udp_packet_count]->data) {
        perror("Unable to allocate memory");
        exit(EXIT_FAILURE);
    }

    memcpy(udp_packets[udp_packet_count]->data, packet_data, length);

    printf("shalus\n");
    process_udp_packet(udp_packets[udp_packet_count]);

    udp_packet_count++;

    pthread_cond_signal(&packet_cond);
    pthread_mutex_unlock(&packet_mutex);
}

int total_seg_cnt = 0;
pthread_mutex_t total_seg_mutex = PTHREAD_MUTEX_INITIALIZER;


void process_udp_packet(udp_packet_t *udp_packet) {
    if (udp_packet->length < sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t) + sizeof(udp_hdr_t)) {
        return;
    }

    ethernet_hdr_t *eth_header = (ethernet_hdr_t *)udp_packet->data;
    ip_hdr_t *ip_header = (ip_hdr_t *)(udp_packet->data + sizeof(ethernet_hdr_t));
    udp_hdr_t *udp_header = (udp_hdr_t *)(udp_packet->data + sizeof(ethernet_hdr_t) + ip_header->ihl * 4);

    udp_packet->id = ntohs(udp_header->source);  // Assuming ID is source port
    udp_packet->payload = udp_packet->data + sizeof(ethernet_hdr_t) + ip_header->ihl * 4 + sizeof(udp_hdr_t);
    udp_packet->payload_len = ntohs(udp_header->len) - sizeof(udp_hdr_t);

    // printf("Processed UDP Packet: ID: %u, Payload Length: %u\n", udp_packet->id, udp_packet->payload_len);

    // Search for SEG{something to capture} in the payload
    const char *pattern = "SEG{";
    char *payload_str = (char *)udp_packet->payload;
    char *end_of_payload = payload_str + udp_packet->payload_len;

    while (payload_str < end_of_payload) {
        char *start = strstr(payload_str, pattern);
        if (start && start < end_of_payload) {
            start += strlen(pattern);
            char *end = strchr(start, '}');
            if (end && end < end_of_payload) {
                size_t capture_len = end - start;
                char *capture = (char *)malloc(capture_len + 1);
                if (capture) {
                    strncpy(capture, start, capture_len);
                    capture[capture_len] = '\0';
                    printf("Captured: %s\n", capture);
                    total_seg_cnt++;
                    free(capture);
                }
                payload_str = end + 1;  // Continue searching from end of the current match
            } else {
                break;  // No closing brace found
            }
        } else {
            break;  // No starting pattern found
        }
    }
}


void process_packet(const uint8_t *packet_data, uint32_t length) {
    if (length < sizeof(ethernet_hdr_t)) {
        return;
    }

    ethernet_hdr_t *eth_header = (ethernet_hdr_t *)packet_data;
    if (ntohs(eth_header->ethertype) != 0x0800) { // Check if the packet is an IP packet
        return;
    }

    ip_hdr_t *ip_header = (ip_hdr_t *)(packet_data + sizeof(ethernet_hdr_t));
    if (ip_header->protocol != 17) { // Check if the packet is a UDP packet
        return;
    }

    uint16_t ip_header_length = ip_header->ihl * 4;
    if (length < sizeof(ethernet_hdr_t) + ip_header_length + sizeof(udp_hdr_t)) {
        return;
    }

    udp_hdr_t *udp_header = (udp_hdr_t *)(packet_data + sizeof(ethernet_hdr_t) + ip_header_length);

    // udp packet detected
    // printf("UDP Packet: Source Port: %u, Destination Port: %u\n",
        //    ntohs(udp_header->source), ntohs(udp_header->dest));

    add_udp_packet(packet_data, length);
}

void read_pcap_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Unable to open file");
        exit(EXIT_FAILURE);
    }

    pcap_hdr_t global_header;
    fread(&global_header, sizeof(pcap_hdr_t), 1, fp);

    if (global_header.magic_number != 0xa1b2c3d4 && global_header.magic_number != 0xd4c3b2a1) {
        fprintf(stderr, "Invalid pcap file\n");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    while (1) {
        pcaprec_hdr_t packet_header;
        size_t read_size = fread(&packet_header, sizeof(pcaprec_hdr_t), 1, fp);
        if (read_size != 1) {
            break;
        }

        uint8_t *packet_data = (uint8_t *)malloc(packet_header.incl_len);
        fread(packet_data, packet_header.incl_len, 1, fp);

        // Process packet data
        process_packet(packet_data, packet_header.incl_len);

        free(packet_data);
    }

    fclose(fp);
}

void free_udp_packets() {
    for (size_t i = 0; i < udp_packet_count; i++) {
        free(udp_packets[i]->data);
        free(udp_packets[i]);
    }
    free(udp_packets);
}

void *reader_thread(void *arg) {
    printf("- Reader thread initialized\n");
    char *filename = (char *)arg;
    read_pcap_file(filename);
    pthread_mutex_lock(&packet_mutex);
    reading_done = 1;
    pthread_cond_broadcast(&packet_cond);  // Notify all workers that reading is done
    pthread_mutex_unlock(&packet_mutex);
    printf("- Reading packets done\n");
    return NULL;
}

thread_id = 0;

void *worker_thread(void *arg) {
    printf("- Worker thread with id %d initialized\n", thread_id++);
    while (1) {
        pthread_mutex_lock(&packet_mutex);

        while (last_read_index >= udp_packet_count && !reading_done) {
            pthread_cond_wait(&packet_cond, &packet_mutex);
        }

        if (last_read_index >= udp_packet_count && reading_done) {
            pthread_mutex_unlock(&packet_mutex);
            break;
        }

        udp_packet_t *udp_packet = udp_packets[last_read_index];
        last_read_index++;
        pthread_mutex_unlock(&packet_mutex);

        process_udp_packet(udp_packet);
    }
    return NULL;
}

#define NUM_WORKER_THREADS 20

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    pthread_t reader;
    pthread_t workers[NUM_WORKER_THREADS];

    // creating reader thread
    pthread_create(&reader, NULL, reader_thread, argv[1]);

    // creating worker threads (processors)
    // for (int i = 0; i < NUM_WORKER_THREADS; i++) {
    //     pthread_create(&workers[i], NULL, worker_thread, NULL);
    // }

    pthread_join(reader, NULL);

    // for (int i = 0; i < NUM_WORKER_THREADS; i++) {
    //     pthread_join(workers[i], NULL);
    // }

    printf("Total UDP packets: %zu\n", udp_packet_count);

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed_time = (end_time.tv_sec - start_time.tv_sec) + 
                          (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    printf("Elapsed time: %.2f seconds\n", elapsed_time);

    printf("Total segments captured: %d\n", total_seg_cnt);

    printf("all udp packets are ready and starting pointer is %p : \n", udp_packets);

    printf("here :\n");
    const char *pattern = "SEG{";
    for (int i=0; i<udp_packet_count; i++){
        udp_packet_t *udp_packet = &udp_packets[i];
        // process_udp_packet(udp_packet);
        ethernet_hdr_t *eth_header = (ethernet_hdr_t *)udp_packet->data;
        ip_hdr_t *ip_header = (ip_hdr_t *)(udp_packet->data + sizeof(ethernet_hdr_t));
        udp_hdr_t *udp_header = (udp_hdr_t *)(udp_packet->data + sizeof(ethernet_hdr_t) + ip_header->ihl * 4);

        // udp_packet->id = ntohs(udp_header->source);  // Assuming ID is source port
        // udp_packet->payload = udp_packet->data + sizeof(ethernet_hdr_t) + ip_header->ihl * 4 + sizeof(udp_hdr_t);
        // udp_packet->payload_len = ntohs(udp_header->len) - sizeof(udp_hdr_t);

        if (i%150==0){
            printf("id is %d\n", ntohs(udp_header->source));
            // printf("len of payload : %u\n", udp_packet->data);
        }

    }

    free_udp_packets();

    return 0;
}
