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
<<<<<<< HEAD
#define NUMBER_OF_THREADS 3
#define THREAD_MEM_SIZE 300
=======
#define NUMBER_OF_THREADS 6
>>>>>>> 6a2b53bc65cda986d0cad8001f0a22d837d62b03

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

void* runner(void* args){

    printf("-Thread started\n");
    struct Arguments* arguments = (struct Arguments*) args;
    pcap_t* handle = arguments->handle;
    segment_t** segments_ptr = arguments->segments_ptr;
    int* mem_cnt = arguments->mem_cnt;
<<<<<<< HEAD
    printf("-Arguments received\n");
       
=======
    int thread_id = arguments->thread_id;
    
    pthread_mutex_lock(&print_mutex);
    printf("thread with id %d initialized\n", thread_id);
    pthread_mutex_unlock(&print_mutex);

>>>>>>> 6a2b53bc65cda986d0cad8001f0a22d837d62b03
    struct pcap_pkthdr pkthdr;

    pthread_mutex_lock(&next_mutex);
    u_char* packet = pcap_next(handle, &pkthdr);
<<<<<<< HEAD
    pthread_mutex_unlock(&mutex);
    printf("-Packet received\n");
    
    // loaded and ready

    if (segments_ptr == NULL){
        printf("-Memory initiazlied in thread\n");
        segments_ptr = (segment_t**)malloc(sizeof(segment_t*));
    }

    printf("-Parsing\n");
=======
    pthread_mutex_unlock(&next_mutex);

    pthread_mutex_lock(&print_mutex);
    printf("thread with id %d captured next packet\n", thread_id);
    pthread_mutex_unlock(&print_mutex);

    // loaded and ready

    if (segments_ptr == NULL){
        pthread_mutex_lock(&print_mutex);
        printf("segment pointer was null and got reallocated\n");
        pthread_mutex_unlock(&print_mutex);
        segments_ptr = (segment_t**)malloc(sizeof(segment_t*));
    }
>>>>>>> 6a2b53bc65cda986d0cad8001f0a22d837d62b03

    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        if (ip_header->ip_p == IPPROTO_UDP) {
<<<<<<< HEAD
            printf("-Found UDP packet\n");
            pthread_mutex_lock(&mutex);
=======
            pthread_mutex_lock(&next_mutex);
>>>>>>> 6a2b53bc65cda986d0cad8001f0a22d837d62b03
            udp_packet_count++;
            pthread_mutex_unlock(&next_mutex);
            
            struct udphdr *udp_header = (struct udphdr *)((u_char*)ip_header + sizeof(struct ip));
            // int id = ntohs(udp_header->uh_sport);
            char *payload = (char *)((u_char*)udp_header + sizeof(struct udphdr));
            int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);

<<<<<<< HEAD
            printf("-Payload :");
            for(int i = 0;i<payload_len;i++)
                printf("%c", payload[i]);
            printf("\n");
=======
            pthread_mutex_lock(&print_mutex);
            printf("ID : ");
            printf("payload : %x\n", payload);
            pthread_mutex_unlock(&print_mutex);
>>>>>>> 6a2b53bc65cda986d0cad8001f0a22d837d62b03
            
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
<<<<<<< HEAD
    // printf("%d\n", ()&packet);
=======
    // printf("%d\n", &packet);
>>>>>>> 6a2b53bc65cda986d0cad8001f0a22d837d62b03
    // printf("%d\n", pkthdr.len);


    struct Arguments *args_arr[NUMBER_OF_THREADS];
    
    pthread_t threads[NUMBER_OF_THREADS];
<<<<<<< HEAD
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
=======
    pthread_t thread_ids[NUMBER_OF_THREADS];

    for (int i=0; i<NUMBER_OF_THREADS; i++){
        
        args_arr[i] = (struct Arguments*) malloc(sizeof(struct Arguments));
        args_arr[i]->handle = handle;
        args_arr[i]->mem_cnt = (int*) malloc(sizeof(int));
        args_arr[i]->segments_ptr = (segment_t**) malloc(sizeof(segment_t*));
        args_arr[i]->thread_id = i;
        
        printf("args is %d\n", args_arr[i]);
        // args_arr[i] = args;
        // thread_ids[i] = (pthread_t) malloc(sizeof(pthread_t));
        pthread_create(&threads[i] , NULL, runner, (void*) args_arr[i]);
    }
    
    for (int i=0; i<NUMBER_OF_THREADS; i++)
        printf("__join -> %d\n", pthread_join(threads[i], NULL));
>>>>>>> 6a2b53bc65cda986d0cad8001f0a22d837d62b03


    // if (pcap_loop(handle, 0, packet_handler, (u_char *)&segments) < 0) {
    //     fprintf(stderr, "Error processing pcap file: %s\n", pcap_geterr(handle));
    //     return 2;
    // }

    // sleep(3);

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
