#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <time.h>

#include<pthread.h>
#include<unistd.h>

#define MAX_PAYLOAD_SIZE 1500
#define NUMBER_OF_THREADS 3
#define THREAD_MEM_SIZE 300

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
} typedef Arguments;

pthread_mutex_t mutex;

void* runner(void* args){

    printf("-Thread started\n");
    struct Arguments* arguments = (struct Arguments*) args;
    pcap_t* handle = arguments->handle;
    segment_t** segments_ptr = arguments->segments_ptr;
    int* mem_cnt = arguments->mem_cnt;
    printf("-Arguments received\n");
       
    struct pcap_pkthdr pkthdr;

    pthread_mutex_lock(&mutex);
    u_char* packet = pcap_next(handle, &pkthdr);
    pthread_mutex_unlock(&mutex);
    printf("-Packet received\n");
    
    // loaded and ready

    if (segments_ptr == NULL){
        printf("-Memory initiazlied in thread\n");
        segments_ptr = (segment_t**)malloc(sizeof(segment_t*));
    }

    printf("-Parsing\n");

    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        if (ip_header->ip_p == IPPROTO_UDP) {
            printf("-Found UDP packet\n");
            pthread_mutex_lock(&mutex);
            udp_packet_count++;
            pthread_mutex_unlock(&mutex);
            
            struct udphdr *udp_header = (struct udphdr *)((u_char*)ip_header + sizeof(struct ip));
            // int id = ntohs(udp_header->uh_sport);
            char *payload = (char *)((u_char*)udp_header + sizeof(struct udphdr));
            int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);

            printf("-Payload :");
            for(int i = 0;i<payload_len;i++)
                printf("%c", payload[i]);
            printf("\n");
            
            // Check for the SEG{} pattern anywhere in the payload
            for (int i = 0; i <= payload_len - 5; i++) {
                if (strncmp(payload + i, "SEG{", 4) == 0) {
                    char *start = payload + i + 4;
                    char *end = strchr(start, '}');
                    if (end) {
                        int seg_len = end - start;
                        if (seg_len > 0 && seg_len < MAX_PAYLOAD_SIZE) {
                            // *segments_ptr = realloc(*segments_ptr, (segment_count + 1) * sizeof(segment_t));
                            segment_t*one_seg = (segment_t*)malloc(sizeof(segment_t));
                            strncpy(one_seg->payload, start, seg_len);
                            printf("seg : %s\n", one_seg->payload);
                            // strncpy((*segments_ptr)[segment_count].payload, start, seg_len);
                            // (*segments_ptr)[segment_count].payload[seg_len] = '\0';
                            // (*segments_ptr)[segment_count].id = id;
                            // segment_count++;
                            break; // Stop after finding the first valid segment in the payload
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
    char *json_file = "temp/output.json";
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    // segment_t *segments = NULL;


    handle = pcap_open_offline(pcap_file, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open adjusted pcap file %s: %s\n", pcap_file, errbuf);
        return 2;
    }

    // following shows that pcap_next works
    // struct pcap_pkthdr pkthdr;
    // u_char* packet = pcap_next(handle, &pkthdr);
    // printf("%d\n", ()&packet);
    // printf("%d\n", pkthdr.len);


    struct Arguments args_arr[NUMBER_OF_THREADS];
    pthread_t threads[NUMBER_OF_THREADS];
    int mem_cnt[NUMBER_OF_THREADS];
    segment_t segments[THREAD_MEM_SIZE * NUMBER_OF_THREADS];
    // pthread_t tid[NUMBER_OF_THREADS];

    for (int i=0; i<NUMBER_OF_THREADS; i++){
        struct Arguments args;
        args.handle = handle;
        args.mem_cnt = &mem_cnt[i];
        args.segments_ptr = &segments[i*THREAD_MEM_SIZE];

        args_arr[i] = args;
        pthread_create(&threads[i], NULL, runner, (void*) &args);
    }
    
    for (int i=0; i<NUMBER_OF_THREADS; i++){
        printf("Thread Output : %d\n", pthread_join(threads[i], NULL));
        // pthread_join(threads[i], NULL);
    }


    // if (pcap_loop(handle, 0, packet_handler, (u_char *)&segments) < 0) {
    //     fprintf(stderr, "Error processing pcap file: %s\n", pcap_geterr(handle));
    //     return 2;
    // }

    sleep(3);

    pcap_close(handle);

    write_segments_to_json(segments, segment_count, json_file);

    // free(segments);

    clock_t end_time = clock();
    double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("Segments extracted and written to %s\n", json_file);
    printf("Total UDP packets: %d\n", udp_packet_count);
    printf("Elapsed time: %.2f seconds\n", elapsed_time);

    return 0;
}
