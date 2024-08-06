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
#include <stdbool.h>

#define MAX_PAYLOAD_SIZE 1500
#define NUMBER_OF_READER_THREADS 1
#define NUMBER_OF_HANDLER_THREADS 3
#define NUMBER_OF_ALL_SIGNATURES 65534  // came from cheat code :)
#define NUMBER_OF_ALL_UDP_PACKETS 50 * 1024  // the large file has 42 million udp packets
#define MAX_STRING_LEN 33  // maximum len of a payload sequence of characters : 32 characters + 1 for null terminator '\0'

typedef struct {
    int id;
    char payload[MAX_PAYLOAD_SIZE];
    int payload_len;
} segment_t;

// segment_t all_segments[NUMBER_OF_ALL_UDP_PACKETS];  // to save all udp packets
segment_t* all_segments; 

// segment_t all_segments_2[NUMBER_OF_ALL_UDP_PACKETS];  // to save all udp packets

segment_t signatured_segments[NUMBER_OF_ALL_SIGNATURES];    // to save all signatured packets
long long signatured_segments_index= 0;
pthread_mutex_t signatured_segments_mutex = PTHREAD_MUTEX_INITIALIZER;   // each thread shall lock this and add to signatured_segments array
                                                                        // it should also increment signatured_segments_index

unsigned int udp_packet_count = 0;  // saves the number of all udp packet read  

pthread_mutex_t read_packet_mutex = PTHREAD_MUTEX_INITIALIZER;  // mutex to read a packet with pcap_next
pthread_mutex_t udp_packet_mutex = PTHREAD_MUTEX_INITIALIZER;   // mutex to increment number of udp packets read

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

// pthread_mutex_t array_mutex = PTHREAD_MUTEX_INITIALIZER;    // a mutex lock used only by reader thread to write to payloads_arr, ids_arr and flag_arr
//                                                             // this mutex lock is used to increment (and %) reader_array_idx

typedef struct {
    pcap_t* handle;
    int thread_id;
    segment_t* all_segments;    // array to save all udp packets in 
    // int* reader_done;
} ReaderArguments;

void* reader_function(void* args) {
    ReaderArguments* arguments = (ReaderArguments*)args;
    pcap_t* handle = arguments->handle;
    int thread_id = arguments->thread_id;
    segment_t* segments = arguments->all_segments;

    long long reader_array_idx = 0;
    printf("- Reader thread initialized with id %d\n", thread_id);
    printf("- \tsegments ptr: %p\n", segments);

    struct pcap_pkthdr pkthdr;
    
    bool flag = true;

    while (flag){
        pthread_mutex_lock(&read_packet_mutex);
        u_char* packet = pcap_next(handle, &pkthdr);
        pthread_mutex_unlock(&read_packet_mutex);
        if (packet == NULL || reader_array_idx > NUMBER_OF_ALL_UDP_PACKETS){
            printf("* No more packets available for Reader thread with ID %d\n", thread_id);
            flag = false;
            break;
        }
        else{   // read a packet
            struct ether_header *eth_header = (struct ether_header *)packet;
            if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
                struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
                if (ip_header->ip_p == IPPROTO_UDP) {
                    // found UDP packet
                    // pthread_mutex_lock(&udp_packet_mutex);
                    udp_packet_count++;
                    // pthread_mutex_unlock(&udp_packet_mutex);

                    // so far, the udp packet has been captured
                    // we will extract payload from it and let packet handlers handle it !  
                    struct udphdr *udp_header = (struct udphdr *)((u_char*)ip_header + sizeof(struct ip));
                    int id = ntohs(udp_header->source); // maybe uh_sport
                    char *payload = (char *)((u_char*)udp_header + sizeof(struct udphdr));
                    int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);

                    // pthread_mutex_lock(&array_mutex);
                    strncpy(segments[reader_array_idx].payload, payload, payload_len);
                    segments[reader_array_idx].id = id;
                    segments[reader_array_idx].payload_len = payload_len;
                    reader_array_idx++;
                    // pthread_mutex_unlock(&array_mutex);
                }
            }
        }
    }
}

typedef struct {
    int thread_id;
    segment_t* all_segments;    // array of all udp packets read and ready to process
    segment_t* captured;        // array to save all signatured packets 
    long long starting_idx;   // thread shall start from all_segments[starting_idx]
    long long ending_idx;     // thread shall end at all_segments[ending_idx]
    long long* read_cnt;    // used to save the number of signatures found by a thread
} HandlerArguments;

const char* pattern = "SEG{";   // pattern to find in payload

void* handler_function(void* args){
    HandlerArguments* arguments = (HandlerArguments*)args;
    long long start_idx = arguments->starting_idx;
    long long end_idx = arguments->ending_idx;
    segment_t* segments = arguments->all_segments;
    segment_t* captured = arguments->captured;
    int thread_id = arguments->thread_id;
    long long* read_cnt = arguments->read_cnt;

    printf("- Worker thread initialized with id %d\n", thread_id);
    printf(" -- starting_idx: %lld\t\tending_idx: %lld\n", start_idx, end_idx);

    for (int idx=start_idx; idx<end_idx; idx++){
        // TODO: process one packet
        char* payload = segments[idx].payload;
        // char* payload_str = payload;
        // char* payload_str = segments[idx].payload;
        // char* end_of_payload = payload + strlen(payload);
        // char* end_of_payload = payload_str + strlen(payload_str);
        int payload_len = segments[idx].payload_len;

        for (int i = 0; i <= payload_len - 5; i++) {
            if (strncmp(payload + i, "SEG{", 4) == 0) {
                char *start = payload + i + 4;
                char *end = strchr(start, '}');
                if (end) {
                    int seg_len = end - start;
                    if (seg_len > 0 && seg_len < MAX_PAYLOAD_SIZE) {
                        pthread_mutex_lock(&signatured_segments_mutex);
                        strncpy(captured[signatured_segments_index].payload, start, seg_len);
                        captured[signatured_segments_index].payload[seg_len] = '\0';
                        captured[signatured_segments_index].id = segments[idx].id;
                        captured[signatured_segments_index].payload_len = seg_len;
                        (*read_cnt) += 1;
                        signatured_segments_index += 1;
                        pthread_mutex_unlock(&signatured_segments_mutex);
                        // *segments_ptr = realloc(*segments_ptr, (segment_count + 1) * sizeof(segment_t));
                        // strncpy((*segments_ptr)[segment_count].payload, start, seg_len);
                        // (*segments_ptr)[segment_count].payload[seg_len] = '\0';
                        // (*segments_ptr)[segment_count].id = id;
                        // segment_count++;
                        break; // Stop after finding the first valid segment in the payload
                    }
                }
            }
        }

        // while (payload_str < end_of_payload) {
        //     char* start = strstr(payload_str, pattern);
        //     if (start && start < end_of_payload) {
        //         printf("shalus ");
        //         start += strlen(pattern);
        //         char* end = strchr(start, '}');
        //         if (end && end < end_of_payload) {
        //             size_t capture_len = end - start;
        //             // found a signature
        //             pthread_mutex_lock(&signatured_segments_mutex);
        //             // printf("was %d and went to ", captured[signatured_segments_index].id);
        //             *(&captured[signatured_segments_index].id) = segments[idx].id;
        //             // printf("%d\n", captured[signatured_segments_index].id);
        //             strncpy(captured[signatured_segments_index].payload, start, capture_len);
        //             // signatured_segments[idx].payload[capture_len] = '\0';
        //             signatured_segments_index += 1;
        //             (*read_cnt)+=1;
        //             payload_str = end + 1;
        //             pthread_mutex_unlock(&signatured_segments_mutex);
        //         } else {
        //             break;
        //         }
        //     } else break;
        // }
    
    }
    return NULL;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file_path>\n", argv[0]);
        return 1;
    }       

    printf("all segments initialized: %p\n", &all_segments);

    all_segments = (segment_t*) malloc(sizeof(segment_t) * NUMBER_OF_ALL_UDP_PACKETS);
    printf("malloc done\n");

    // clock_t start_time = clock();
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    char *pcap_file = argv[1];
    char *json_file = "./temp/output.json";
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(pcap_file, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap file %s: %s\n", pcap_file, errbuf);
        return 2;
    }
    printf("pacp file opened succesfully\n");

    pthread_t reader_threads[NUMBER_OF_READER_THREADS];
    pthread_t handler_threads[NUMBER_OF_HANDLER_THREADS];

    // creating reader threads
    ReaderArguments *reader_args_arr[NUMBER_OF_READER_THREADS];
    for (int i = 0; i < NUMBER_OF_READER_THREADS; i++) {
        reader_args_arr[i] = malloc(sizeof(ReaderArguments));
        reader_args_arr[i]->handle = handle;
        reader_args_arr[i]->thread_id = i;
        reader_args_arr[i]->all_segments = all_segments;
        pthread_create(&reader_threads[i], NULL, reader_function, (void*)reader_args_arr[i]);
    }
    
    for (int i = 0; i < NUMBER_OF_READER_THREADS; i++) {
        pthread_join(reader_threads[i], NULL);
    }  

    // for (int i=0; i<udp_packet_count; i++){
    //     printf("packet with id %d and payload %s\n", all_segments[i].id, all_segments[i].payload);
    // }
    
    HandlerArguments *handler_args_arr[NUMBER_OF_HANDLER_THREADS];
    long long starting_idx = 0;
    long long ending_idx = (long long)(udp_packet_count / NUMBER_OF_HANDLER_THREADS);
    long long step = (long long)(udp_packet_count / NUMBER_OF_HANDLER_THREADS);

    long long* all_read_cnts = (long long*) calloc(NUMBER_OF_HANDLER_THREADS, sizeof(long long));
    for (int i = 0; i < NUMBER_OF_HANDLER_THREADS; i++) {
        handler_args_arr[i] = malloc(sizeof(HandlerArguments));
        handler_args_arr[i]->thread_id = i;
        handler_args_arr[i]->all_segments = all_segments;
        handler_args_arr[i]->captured = signatured_segments;
        handler_args_arr[i]->starting_idx = starting_idx;
        handler_args_arr[i]->ending_idx = ending_idx;
        starting_idx += step;
        ending_idx += step;
        handler_args_arr[i]->read_cnt = &all_read_cnts[i];
        // pthread_create(&handler_threads[i], NULL, handler_function, (void*)handler_args_arr[i]);
    }
    for (int i = 0; i < NUMBER_OF_HANDLER_THREADS; i++) {
        // pthread_join(handler_threads[i], NULL);
    }  

    long long total_cnt = 0;
    for (int i=0; i<NUMBER_OF_HANDLER_THREADS; i++) total_cnt += all_read_cnts[i];

    usleep(50);

    pcap_close(handle);

    write_segments_to_json(signatured_segments, total_cnt, json_file);
    printf("writing to json done\n");

    free(all_segments);
    // free(signatured_segments);

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed_time = (end_time.tv_sec - start_time.tv_sec) + 
                          (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    // printf("Segments extracted and written to %s\n", json_file);
    printf("Total UDP packets: %d\n", udp_packet_count);
    printf("Total segments: %lld\n", total_cnt);
    printf("Elapsed time: %.2f seconds\n", elapsed_time);

    printf("done and done\n");
    return 0;
}
