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
#define NUMBER_OF_THREADS 3
#define THREAD_MEM_SIZE 300
#define CUDA_THREADS_PER_BLOCK 256

typedef struct {
    int id;
    char payload[MAX_PAYLOAD_SIZE];
} segment_t;

int segment_count = 0;
unsigned int udp_packet_count = 0;

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

struct Arguments
{
    pcap_t* handle;
    segment_t** segments_ptr;
    int* mem_cnt;
    int thread_id;
} typedef Arguments;

pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t next_mutex = PTHREAD_MUTEX_INITIALIZER;

__device__ unsigned short d_ntohs(unsigned short val) {
    return (val << 8) | (val >> 8);
}

__device__ int d_strncmp(const char *s1, const char *s2, size_t n) {
    while (n && *s1 && (*s1 == *s2)) {
        ++s1;
        ++s2;
        --n;
    }
    if (n == 0) {
        return 0;
    } else {
        return (*(unsigned char *)s1 - *(unsigned char *)s2);
    }
}

__device__ char* d_strchr(const char *s, int c) {
    while (*s != (char)c) {
        if (!*s++) {
            return 0;
        }
    }
    return (char *)s;
}

__device__ char* d_strncpy(char *dest, const char *src, size_t n) {
    char *ret = dest;
    while (n && (*dest++ = *src++)) {
        --n;
    }
    if (n) {
        while (--n) {
            *dest++ = 0;
        }
    }
    return ret;
}

__global__ void process_packets(const u_char *packet_data, segment_t *segments, int *mem_cnt, int total_packets) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= total_packets) return;

    const u_char *packet = packet_data + idx * MAX_PAYLOAD_SIZE;
    struct ether_header *eth_header = (struct ether_header *)packet;

    if (d_ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        if (ip_header->ip_p == IPPROTO_UDP) {
            atomicAdd(&udp_packet_count, 1);

            struct udphdr *udp_header = (struct udphdr *)((u_char*)ip_header + sizeof(struct ip));
            char *payload = (char *)((u_char*)udp_header + sizeof(struct udphdr));
            int payload_len = d_ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);

            for (int i = 0; i <= payload_len - 5; i++) {
                if (d_strncmp(payload + i, "SEG{", 4) == 0) {
                    char *start = payload + i + 4;
                    char *end = d_strchr(start, '}');
                    if (end) {
                        int seg_len = end - start;
                        if (seg_len > 0 && seg_len < MAX_PAYLOAD_SIZE) {
                            int mem_idx = atomicAdd(mem_cnt, 1);
                            d_strncpy(segments[mem_idx].payload, start, seg_len);
                            segments[mem_idx].payload[seg_len] = '\0';
                            break;
                        }
                    }
                }
            }
        }
    }
}

void* runner(void* args){
    printf("-Thread started\n");
    struct Arguments* arguments = (struct Arguments*) args;
    pcap_t* handle = arguments->handle;
    segment_t** segments_ptr = arguments->segments_ptr;
    int* mem_cnt = arguments->mem_cnt;
    printf("-Arguments received\n");
       
    int thread_id = arguments->thread_id;
    
    pthread_mutex_lock(&print_mutex);
    printf("thread with id %d initialized\n", thread_id);
    pthread_mutex_unlock(&print_mutex);

    struct pcap_pkthdr pkthdr;

    int flag = 1;
    while (flag) {

        pthread_mutex_lock(&next_mutex);
        u_char* packet = pcap_next(handle, &pkthdr);
        pthread_mutex_unlock(&next_mutex);
        if (packet == NULL){
            printf("no more packets available for thread with ID %d\n", thread_id);
            pthread_exit(NULL);
            return NULL;
        }

        pthread_mutex_lock(&print_mutex);
        // printf("thread with id %d captured next packet\n", thread_id);
        pthread_mutex_unlock(&print_mutex);

        // loaded and ready

        if (segments_ptr == NULL){
            pthread_mutex_lock(&print_mutex);
            printf("segment pointer was null and got reallocated\n");
            pthread_mutex_unlock(&print_mutex);
            segments_ptr = (segment_t**)malloc(sizeof(segment_t*));
        }

        // Allocate device memory
        u_char *d_packet_data;
        segment_t *d_segments;
        int *d_mem_cnt;

        int total_packets = 1; // This needs to be set appropriately
        cudaMalloc((void**)&d_packet_data, MAX_PAYLOAD_SIZE * total_packets);
        cudaMalloc((void**)&d_segments, sizeof(segment_t) * THREAD_MEM_SIZE);
        cudaMalloc((void**)&d_mem_cnt, sizeof(int));

        // Copy data to device
        cudaMemcpy(d_packet_data, packet, MAX_PAYLOAD_SIZE * total_packets, cudaMemcpyHostToDevice);
        cudaMemcpy(d_mem_cnt, mem_cnt, sizeof(int), cudaMemcpyHostToDevice);

        // Launch kernel
        int num_blocks = (total_packets + CUDA_THREADS_PER_BLOCK - 1) / CUDA_THREADS_PER_BLOCK;
        process_packets<<<num_blocks, CUDA_THREADS_PER_BLOCK>>>(d_packet_data, d_segments, d_mem_cnt, total_packets);

        // Copy results back to host
        cudaMemcpy(segments_ptr, d_segments, sizeof(segment_t) * THREAD_MEM_SIZE, cudaMemcpyDeviceToHost);
        cudaMemcpy(mem_cnt, d_mem_cnt, sizeof(int), cudaMemcpyDeviceToHost);

        // Free device memory
        cudaFree(d_packet_data);
        cudaFree(d_segments);
        cudaFree(d_mem_cnt);
    }

    return NULL;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file_path>\n", argv[0]);
        return 1;
    }

    clock_t start_time = clock();

    char *pcap_file = argv[1];
    char *json_file = "temp/output.json";
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    // segment_t *segments = NULL;

    handle = pcap_open_offline(pcap_file, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open adjusted pcap file %s: %s\n", pcap_file, errbuf);
        return 2;
    }

    struct Arguments *args_arr[NUMBER_OF_THREADS];
    
    pthread_t threads[NUMBER_OF_THREADS];
    int mem_cnt[NUMBER_OF_THREADS] = {0};
    segment_t segments[THREAD_MEM_SIZE * NUMBER_OF_THREADS];

    for (int i = 0; i < NUMBER_OF_THREADS; i++) {
        args_arr[i] = (struct Arguments*)malloc(sizeof(struct Arguments));
        args_arr[i]->handle = handle;
        args_arr[i]->mem_cnt = &mem_cnt[i];
        args_arr[i]->segments_ptr = &segments[i * THREAD_MEM_SIZE];
        args_arr[i]->thread_id = i;

        pthread_create(&threads[i], NULL, runner, (void*)args_arr[i]);
    }

    for (int i = 0; i < NUMBER_OF_THREADS; i++) {
        printf("Thread Output: %d\n", pthread_join(threads[i], NULL));
    }

    int total_segments = 0;
    for (int i = 0; i < NUMBER_OF_THREADS; i++) {
        total_segments += mem_cnt[i];
    }
    printf("Total SEGs captured: %d\n", total_segments);

    pcap_close(handle);

    write_segments_to_json(segments, total_segments, json_file);

    clock_t end_time = clock();
    double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("Segments extracted and written to %s\n", json_file);
    printf("Total UDP packets: %d\n", udp_packet_count);
    printf("Elapsed time: %.2f seconds\n", elapsed_time);

    return 0;
}
