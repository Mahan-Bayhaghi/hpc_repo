#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <time.h>
#include <pthread.h>


#define MAX_PAYLOAD_SIZE 1500
#define NUMBER_OF_HANDLER_THREADS 16
#define NUMBER_OF_ALL_SIGNATURES 65534  // result of peeking output.json :)
#define INITIAL_BUFFER_SIZE 4 * 1024 * 1024

pthread_mutex_t packet_mutex = PTHREAD_MUTEX_INITIALIZER; // mutex for packet processing

u_char **packet_buffer = NULL;
int *packet_lengths = NULL;

int packet_count = 0;
int buffer_size = INITIAL_BUFFER_SIZE;

typedef struct {
    int id;
    char payload[MAX_PAYLOAD_SIZE];
} segment_t;

int segment_count = 0;
unsigned int udp_packet_count = 0;

void write_segments_to_json(segment_t *segments, int count, const char *filename) {
    json_t *json_segments = json_array();
    for (int i = 0; i < count; i++) {
        if (segments[i].payload[0] != '\0') {
            json_t *json_segment = json_object();
            json_object_set_new(json_segment, "id", json_integer(segments[i].id));
            json_object_set_new(json_segment, "payload", json_string(segments[i].payload));
            json_array_append_new(json_segments, json_segment);
        }
    }
    json_dump_file(json_segments, filename, JSON_INDENT(4));
    json_decref(json_segments);
}

typedef struct {
    int thread_id;
    int start_packet;
    // int num_packets;
    int ending_packet;
    pthread_mutex_t *mutex;
    segment_t *segments;
} HandlerArguments;

void *handler_function(void *arg) {
    HandlerArguments *handler_args = (HandlerArguments *)arg;
    int start_packet = handler_args->start_packet;
    int end_packet = handler_args->ending_packet;
    for (int idx = start_packet; idx < end_packet && idx < packet_count; idx++) {
        const u_char *packet = packet_buffer[idx];
        int length = packet_lengths[idx];

        if (length < sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)) continue; 

        struct ether_header *eth_header = (struct ether_header *)packet;
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
            if (ip_header->ip_p == IPPROTO_UDP) {
                pthread_mutex_lock(handler_args->mutex);
                udp_packet_count++;
                pthread_mutex_unlock(handler_args->mutex);

                struct udphdr *udp_header = (struct udphdr *)((u_char*)ip_header + sizeof(struct ip));
                int id = ntohs(udp_header->uh_sport);
                char *payload = (char *)((u_char*)udp_header + sizeof(struct udphdr));
                int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);

                // truncuate len to a valid length
                if (payload_len > length - (udp_header - (struct udphdr *)ip_header)) {
                    payload_len = length - (udp_header - (struct udphdr *)ip_header);
                }

                // alright this works on single thread but could we make it even faster ?
                for (int j = 0; j <= payload_len - 5; j++) {
                    if (strncmp(payload + j, "SEG{", 4) == 0) {
                        char *start = payload + j + 4;
                        char *end = strchr(start, '}');
                        if (end) {
                            int seg_len = end - start;
                            if (seg_len > 0 && seg_len < MAX_PAYLOAD_SIZE) {
                                if (id < NUMBER_OF_ALL_SIGNATURES) {
                                    pthread_mutex_lock(handler_args->mutex);
                                    strncpy(handler_args->segments[id].payload, start, seg_len);
                                    handler_args->segments[id].payload[seg_len] = '\0';
                                    handler_args->segments[id].id = id;
                                    if (id >= segment_count) {
                                        segment_count = id + 1;
                                    }
                                    pthread_mutex_unlock(handler_args->mutex);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file_path>\n", argv[0]);
        return 1;
    }

    struct timespec read_start, read_end, start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    clock_gettime(CLOCK_MONOTONIC, &read_start);

    char *pcap_file = argv[1];
    char *json_file = "./temp/output.json";
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *packet;

    segment_t *segments = calloc(NUMBER_OF_ALL_SIGNATURES, sizeof(segment_t));
    if (segments == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap file %s: %s\n", pcap_file, errbuf);
        free(segments);
        return 2;
    }

    printf("Beginning allocations done\n");

    // we will use berkley packet filtering to further decrease readin time :)
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter\n");
        pcap_close(handle);
        free(segments);
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter\n");
        pcap_close(handle);
        free(segments);
        return 2;
    }
    pcap_freecode(&fp);
    
    // now, there should only remain udp packets
    packet_buffer = malloc(buffer_size * sizeof(u_char *));
    packet_lengths = malloc(buffer_size * sizeof(int));
    if (packet_buffer == NULL || packet_lengths == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        free(segments);
        return 1;
    }

    // simply read all packets
    while (pcap_next_ex(handle, &header, &packet) == 1) {
        if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)) continue; 
        if (header->len >= sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)) {
            if (packet_count >= buffer_size) {
                buffer_size *= 2;   // if buffer was not large enough !
                packet_buffer = realloc(packet_buffer, buffer_size * sizeof(u_char *));
                packet_lengths = realloc(packet_lengths, buffer_size * sizeof(int));
                if (packet_buffer == NULL || packet_lengths == NULL) {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(segments);
                    return 1;
                }
            }
            packet_buffer[packet_count] = malloc(header->caplen);
            if (packet_buffer[packet_count] == NULL) {
                fprintf(stderr, "Memory allocation failed\n");
                free(segments);
                return 1;
            }
            memcpy((void *)packet_buffer[packet_count], packet, header->caplen);
            packet_lengths[packet_count] = header->caplen;
            packet_count++;
        }
    }
    
    pcap_close(handle);

    clock_gettime(CLOCK_MONOTONIC, &read_end);
    double read_time = (read_end.tv_sec - read_start.tv_sec) + (read_end.tv_nsec - read_start.tv_nsec) / 1e9;
    printf("Reading Elapsed time: %.4f seconds\n", read_time);

    printf("packets are loaded and ready to process\n");

    pthread_t handler_threads[NUMBER_OF_HANDLER_THREADS];
    HandlerArguments handler_args[NUMBER_OF_HANDLER_THREADS];

    int step = (packet_count / NUMBER_OF_HANDLER_THREADS);
    for (int i = 0; i < NUMBER_OF_HANDLER_THREADS; i++) {
        handler_args[i].thread_id = i;
        handler_args[i].start_packet = i * step;
        // handler_args[i].num_packets = (i == NUMBER_OF_HANDLER_THREADS - 1) ? (packet_count - i * step) : step;
        int num_packets_for_this_thread = (i == NUMBER_OF_HANDLER_THREADS - 1) ? (packet_count - i * step) : step;
        int end_packet = i*step + num_packets_for_this_thread;
        handler_args[i].ending_packet = end_packet;
        handler_args[i].mutex = &packet_mutex;
        handler_args[i].segments = segments;

        pthread_create(&handler_threads[i], NULL, handler_function, &handler_args[i]);
    }

    for (int i = 0; i < NUMBER_OF_HANDLER_THREADS; i++) {
        pthread_join(handler_threads[i], NULL);
    }

    write_segments_to_json(segments, segment_count, json_file);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("Segments extracted and written to %s\n", json_file);
    printf("Total UDP packets: %u\n", udp_packet_count);
    printf("Elapsed time: %.4f seconds\n", elapsed_time);
    return 0;
}
