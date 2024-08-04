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
#include <unistd.h>

#define MAX_PAYLOAD_SIZE 1500
#define NUMBER_OF_THREADS 4
#define THREAD_MEM_SIZE 300

typedef struct {
    int id;
    char payload[MAX_PAYLOAD_SIZE];
} segment_t;

typedef struct {
    pcap_t* handle;
    segment_t* segments;
    int* mem_cnt;
    int thread_id;
} Arguments;

int segment_count = 0;
unsigned int udp_packet_count = 0;

pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t next_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t segment_mutex = PTHREAD_MUTEX_INITIALIZER;

void write_segments_to_json(segment_t *segments, int count, const char *filename) {
    json_t *json_segments = json_array();
    for (int i = 0; i < count; i++) {
        json_t *json_segment = json_object();
        json_object_set_new(json_segment, "id", json_integer(segments[i].id));
        json_object_set_new(json_segment, "payload", json_string(segments[i].payload));
        json_array_append_new(json_segments, json_segment);
    }
    json_dump_file(json_segments, filename, JSON_INDENT(4));
    json_decref(json_segments);
}

void* runner(void* args) {
    printf("-Thread started\n");
    Arguments* arguments = (Arguments*)args;
    pcap_t* handle = arguments->handle;
    segment_t* segments = arguments->segments;
    int* mem_cnt = arguments->mem_cnt;
    int thread_id = arguments->thread_id;

    pthread_mutex_lock(&print_mutex);
    printf("thread with id %d initialized\n", thread_id);
    pthread_mutex_unlock(&print_mutex);

    struct pcap_pkthdr pkthdr;

    while (1) {
        printf("thread %d waiting for next lock %p\n", thread_id, &next_mutex);
        pthread_mutex_lock(&next_mutex);
        printf("thread %d accuired next lock %p\n", thread_id, &next_mutex);
        u_char* packet = pcap_next(handle, &pkthdr);
        pthread_mutex_unlock(&next_mutex);
        printf("thread %d released next lock %p\n", thread_id, &next_mutex);
        if (packet == NULL) {
            pthread_mutex_lock(&print_mutex);
            printf("no more packets available for thread with ID %d\n", thread_id);
            pthread_mutex_unlock(&print_mutex);
            pthread_exit(NULL);
        }

        struct ether_header *eth_header = (struct ether_header *)packet;
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
            if (ip_header->ip_p == IPPROTO_UDP) {
                pthread_mutex_lock(&print_mutex);
                // printf("-Found UDP packet\n");
                pthread_mutex_unlock(&print_mutex);

                pthread_mutex_lock(&segment_mutex);
                udp_packet_count++;
                pthread_mutex_unlock(&segment_mutex);

                struct udphdr *udp_header = (struct udphdr *)((u_char*)ip_header + sizeof(struct ip));
                int id = ntohs(udp_header->uh_sport);
                char *payload = (char *)((u_char*)udp_header + sizeof(struct udphdr));
                int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);

                // printf("packet id is %d\n", id);

                for (int i = 0; i <= payload_len - 5; i++) {
                    if (strncmp(payload + i, "SEG{", 4) == 0) {
                        char *start = payload + i + 4;
                        char *end = strchr(start, '}');
                        if (end) {
                            int seg_len = end - start;
                            if (seg_len > 0 && seg_len < MAX_PAYLOAD_SIZE) {
                                pthread_mutex_lock(&segment_mutex);
                                strncpy(segments[*mem_cnt].payload, start, seg_len);
                                segments[*mem_cnt].payload[seg_len] = '\0';
                                segments[*mem_cnt].id = id;
                                (*mem_cnt)++;
                                pthread_mutex_unlock(&segment_mutex);
                                break; // Stop after finding the first valid segment in the payload
                            }
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file_path>\n", argv[0]);
        return 1;
    }

    clock_t start_time = clock();

    char *pcap_file = argv[1];
    char *json_file = "./temp/output.json";
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(pcap_file, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap file %s: %s\n", pcap_file, errbuf);
        return 2;
    }

    pthread_t threads[NUMBER_OF_THREADS];
    Arguments *args_arr[NUMBER_OF_THREADS];
    segment_t segments[THREAD_MEM_SIZE * NUMBER_OF_THREADS];
    int mem_cnt[NUMBER_OF_THREADS] = {0};

    for (int i = 0; i < NUMBER_OF_THREADS; i++) {
        args_arr[i] = malloc(sizeof(Arguments));
        args_arr[i]->handle = handle;
        args_arr[i]->segments = segments + (i * THREAD_MEM_SIZE);
        args_arr[i]->mem_cnt = &mem_cnt[i];
        args_arr[i]->thread_id = i;
        pthread_create(&threads[i], NULL, runner, (void*) args_arr[i]);
    }

    for (int i = 0; i < NUMBER_OF_THREADS; i++) {
        pthread_join(threads[i], NULL);
        free(args_arr[i]);
    }

    // Concatenate all segments
    int total_segments = 0;
    for (int i = 0; i < NUMBER_OF_THREADS; i++) {
        total_segments += mem_cnt[i];
    }

    segment_t *all_segments = malloc(total_segments * sizeof(segment_t));
    int index = 0;
    for (int i = 0; i < NUMBER_OF_THREADS; i++) {
        for (int j = 0; j < mem_cnt[i]; j++) {
            all_segments[index++] = segments[i * THREAD_MEM_SIZE + j];
        }
    }

    printf("Total SEGs captured: %d\n", total_segments);

    pcap_close(handle);

    write_segments_to_json(all_segments, total_segments, json_file);

    free(all_segments);

    clock_t end_time = clock();
    double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("Segments extracted and written to %s\n", json_file);
    printf("Total UDP packets: %d\n", udp_packet_count);
    printf("Elapsed time: %.2f seconds\n", elapsed_time);

    return 0;
}
