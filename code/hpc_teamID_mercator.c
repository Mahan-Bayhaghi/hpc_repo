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
#define NUMBER_OF_HANDLER_THREADS 8
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

void write_payloads_to_json(char** payloads, int* ids, int count, const char* filename){
    json_t *json_segments = json_array();
    for (int i = 0; i < count; i++) {
        json_t *json_segment = json_object();
        json_object_set_new(json_segment, "id", json_integer(ids[i]));
        json_object_set_new(json_segment, "payload", json_string(payloads[i]));
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
        // printf("thread %d waiting for next lock %p\n", thread_id, &next_mutex);
        pthread_mutex_lock(&next_mutex);
        // printf("thread %d accuired next lock %p\n", thread_id, &next_mutex);
        u_char* packet = pcap_next(handle, &pkthdr);
        pthread_mutex_unlock(&next_mutex);
        // printf("thread %d released next lock %p\n", thread_id, &next_mutex);
        if (packet == NULL || (*mem_cnt) >= 100) {
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

/*
    packet queue definition
*/
#define PACKET_QUEUE_MAX_LEN 200
typedef struct PacketQueue {
    u_char* packet_arr[PACKET_QUEUE_MAX_LEN];
    u_char* back;
    u_char* front;
} PacketQueue;

void initializeQueue(PacketQueue* q){
    q->front = NULL;
    q->back = NULL;
}
bool isEmpty(PacketQueue* q){
    return (q->front == NULL && q->back == NULL);
}
bool isFull(PacketQueue* q){
    return (q->front != NULL || q->back != NULL);
}

/* 
    pcap_reader_runner is a runner function for a thread that is supposed to read from pcap file
    each thread will request next packet and will store it in it's specific queue
    if there is no packet to read from pcap file, thread ends

    args:
        pcap_t* handle: handle of pcap file (loaded offline)
        
        int* arr_idx: index of last unread item of payload_pairs_arr

        PayloadIDPair* payload_pairs_arr: pointer to an array with fixed length PAYLOAD_ID_PAIR_MAX_LEN
            each reader thread will fill this array with pair of (id, payload [*, len]) and increment arr_idx by one

        int thread_id: id of worker thread
        
*/
pthread_mutex_t read_packet_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t udp_packet_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int id;
    char *payload;
    int payload_len;
} PayloadIDPair;

typedef struct {
    pcap_t* handle;
    int thread_id;
    char** payloads_arr;
    int* ids_arr;
    int* flags_arr;
    int* reader_done;
} ReaderArguments;


#define NUM_ENTRIES 1000    // maximum number of packets saved on RAM at the same time
char** payloads_arr;        // an array of strings used to save payloads of packets on memory
int* ids_arr;               // an array of int used to save ids of packets on memory
int* flags_arr;             // an array of int (flag 0/1) used to save if an idx of these 3 arrays are processed or not
                            // if an idx is not processed by worker threads, flag is 1, otherwise it is 0
/*
    payloads_arr, ids_arr and flags_arr are coherent arrays. it means that payload_arr[idx] is payload of packet with id = ids_arr[idx]
    please please please check for any coherency bug !!!!!!!!!!
*/
#define MAX_STRING_LEN 33  // maximum len of a payload sequence of characters : 32 characters + 1 for null terminator '\0'


pthread_mutex_t array_mutex = PTHREAD_MUTEX_INITIALIZER;    // a mutex lock used only by reader thread to write to payloads_arr, ids_arr and flag_arr
                                                            // this mutex lock is used to increment (and %) reader_array_idx

void* pcap_reader_runner(void* args) {
    ReaderArguments* arguments = (ReaderArguments*)args;
    pcap_t* handle = arguments->handle;
    int thread_id = arguments->thread_id;
    char** payloads_arr_ptr = arguments->payloads_arr;
    int* ids_arr_ptr = arguments->ids_arr;
    int* flags_arr_ptr = arguments->flags_arr;
    int* reader_done = arguments->reader_done;


    int reader_array_idx = 0;

    printf("- Reader thread initialized\n");
    printf("\tpayloads_arr_ptr: %p \n\tids_arr_ptr: %p \n\tflags_arr_ptr: %p\n", payloads_arr_ptr, ids_arr_ptr, flags_arr_ptr);

    struct pcap_pkthdr pkthdr;
    
    int read = 0;

    printf("- Reader thread initialized with id %d\n", thread_id);

    bool flag = true;

    while (flag){
        pthread_mutex_lock(&read_packet_mutex);
        u_char* packet = pcap_next(handle, &pkthdr);
        // similar packet address is given every single time
        // even pkthdrs are all similar !!
        pthread_mutex_unlock(&read_packet_mutex);
        if (packet == NULL){
            pthread_mutex_lock(&print_mutex);
            printf("* No more packets available for thread with ID %d\n", thread_id);
            printf("\t* Read %d packets\n", read);
            pthread_mutex_unlock(&print_mutex);
            flag = false;
            *reader_done = 1; // Signal that reading is done
            break;
        }
        else{
            struct ether_header *eth_header = (struct ether_header *)packet;

            // if (ntohs(eth_header->ether_type) == ETHERTYPE_IP && segment_count < NUM_ENTRIES) {
            if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
                struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
                if (ip_header->ip_p == IPPROTO_UDP) {
                    // printf("-Found UDP packet\n");

                    pthread_mutex_lock(&udp_packet_mutex);
                    udp_packet_count++;
                    pthread_mutex_unlock(&udp_packet_mutex);

                    // so far, the udp packet has been captured
                    // we will extract payload from it and let packet handlers handle it ! 
                    struct udphdr *udp_header = (struct udphdr *)((u_char*)ip_header + sizeof(struct ip));
                    int id = ntohs(udp_header->source); // maybe uh_sport
                    char *payload = (char *)((u_char*)udp_header + sizeof(struct udphdr));
                    int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);

                    // printf("here is shit\n");   
                    pthread_mutex_lock(&array_mutex);
                    strncpy(payloads_arr_ptr[reader_array_idx], payload, payload_len);
                    payloads_arr_ptr[reader_array_idx][payload_len] = '\0';  // Null-terminate the string
                    ids_arr_ptr[reader_array_idx] = id;
                    flags_arr_ptr[reader_array_idx] = 1;
                    reader_array_idx += 1;
                    reader_array_idx %= NUM_ENTRIES;
                    pthread_mutex_unlock(&array_mutex);
                    // printf("here is not\n");
                }
            }
        }
    }
}


typedef struct {
    int thread_id;
    char** payloads_arr_ptr;
    int* ids_arr_ptr;
    int* flags_arr_ptr;
    int *reader_done;
    int* read_cnt;
    char** captured_segments;
    int* captured_ids;
} HandlerArguments;

pthread_mutex_t capture_mutex = PTHREAD_MUTEX_INITIALIZER; 
/*
    pcap_handler_runner is a runner function for threads that are supposed to find signatures
    each thread is always iterating through memmory in array to find a non-processed payload (by it's flag)
    if found, it will ask for capture_mutex
        if given, it will set the flag to 0 and starts processing
        if given but the flag of it's found is still 0, move on !! (really bad idea)
    if there reading packets by reader is done and no packet is in memory (non-processed), thread ends
*/
void* packet_handler_runner(void* args){
    HandlerArguments* arguments = (HandlerArguments*)args;
    int thread_id = arguments->thread_id;
    char** payloads_arr_ptr = arguments->payloads_arr_ptr;
    int* ids_arr_ptr = arguments->ids_arr_ptr;
    int* flags_arr_ptr = arguments->flags_arr_ptr;
    int* reader_done = arguments->reader_done;

    int* read_cnt = arguments->read_cnt;
    char** captured_segments = arguments->captured_segments;
    int* captured_ids = arguments->captured_ids;

    printf("- Worker thread initialized with id %d\n", thread_id);
    printf("\tpayloads_arr_ptr: %p \n\tids_arr_ptr: %p \n\tflags_arr_ptr: %p\n", payloads_arr_ptr, ids_arr_ptr, flags_arr_ptr);

    while (1) {
        int found_packet = 0;
        // pthread_mutex_lock(&array_mutex);
        for (int i = 0; i < NUM_ENTRIES; i++) {
            if (flags_arr_ptr[i] == 1) {
                pthread_mutex_lock(&capture_mutex);
                if (flags_arr_ptr[i] == 1) {
                    flags_arr_ptr[i] = 0;  // Mark as processing
                    pthread_mutex_unlock(&capture_mutex);

                    found_packet += 1;

                    int id = ids_arr_ptr[i];
                    char* payload = payloads_arr_ptr[i];

                    // printf("Thread %d processing packet with ID %d, payload: %s\n", thread_id, id, payload);

                    // Search for SEG{something to capture} in the payload
                    const char* pattern = "SEG{";
                    char* payload_str = payload;
                    char* end_of_payload = payload + strlen(payload);

                    while (payload_str < end_of_payload) {
                        char* start = strstr(payload_str, pattern);
                        if (start && start < end_of_payload) {
                            start += strlen(pattern);
                            char* end = strchr(start, '}');
                            if (end && end < end_of_payload) {
                                size_t capture_len = end - start;
                                // char* capture = (char*)malloc(capture_len + 1);
                                // if (capture) {
                                //     strncpy(capture, start, capture_len);
                                //     capture[capture_len] = '\0';
                                //     printf("Thread %d captured: %s\n", thread_id, capture);
                                //     free(capture);
                                // }
                                strncpy(captured_segments[*read_cnt], start, capture_len);
                                captured_segments[*read_cnt][capture_len] = '\0';
                                captured_ids[*read_cnt] = id;
                                (*read_cnt)+=1;
                                payload_str = end + 1;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                } else {
                    pthread_mutex_unlock(&capture_mutex);
                }
                break;
            }
        }
        // pthread_mutex_unlock(&array_mutex);

        if (!found_packet) {
            pthread_mutex_lock(&udp_packet_mutex);
            int local_udp_packet_count = udp_packet_count;
            pthread_mutex_unlock(&udp_packet_mutex);

            if (*reader_done || local_udp_packet_count == 0) {
                printf("Worker thread %d: no more packets to process, Total found signatures : <%d>,\t\t... terminating.\n", thread_id, *read_cnt);
                break;
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

    payloads_arr = (char**) malloc(NUM_ENTRIES * sizeof(char*));
    for (int entry_idx=0; entry_idx < NUM_ENTRIES; entry_idx++){
        payloads_arr[entry_idx] = malloc(MAX_STRING_LEN * sizeof(char));
    }
    int (*ids_arr) = (int*) calloc(NUM_ENTRIES, sizeof(int));
    int (*flags_arr) = (int*) calloc(NUM_ENTRIES, sizeof(int));

    // for (int i=0; i<NUM_ENTRIES; i++)
    //     printf("%d ", ids_arr[i]);

    if (payloads_arr == NULL || ids_arr == NULL) {
        perror("malloc");
        return 1;
    }
    printf("payloads, IDs and flags arr intialized \n");
    printf("--payloads_arr_ptr: %p \n--ids_arr_ptr: %p \n--flags_arr_ptr: %p\n", payloads_arr, ids_arr, flags_arr);

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

    Arguments *args_arr[NUMBER_OF_READER_THREADS];
    segment_t segments[THREAD_MEM_SIZE * NUMBER_OF_READER_THREADS];

    int reading_done = 0;
    // printf("reading done = %d\n", reading_done);

    // creating reader threads
    ReaderArguments *reader_args_arr[NUMBER_OF_READER_THREADS];
    for (int i = 0; i < NUMBER_OF_READER_THREADS; i++) {
        reader_args_arr[i] = malloc(sizeof(ReaderArguments));
        reader_args_arr[i]->handle = handle;
        reader_args_arr[i]->thread_id = i;
        reader_args_arr[i]->ids_arr = ids_arr;
        reader_args_arr[i]->payloads_arr = payloads_arr;
        reader_args_arr[i]->flags_arr = flags_arr;
        reader_args_arr[i]->reader_done = &reading_done;
        pthread_create(&reader_threads[i], NULL, pcap_reader_runner, (void*)reader_args_arr[i]);
    }


    int** all_read_cnts = (int**) malloc(sizeof(int*) * NUMBER_OF_HANDLER_THREADS);
    for (int i=0; i<NUMBER_OF_HANDLER_THREADS; i++){
        all_read_cnts[i] = (int*) malloc(sizeof(int));
    }

    char*** all_captured_segments = (char***) malloc(sizeof(char**) * NUMBER_OF_HANDLER_THREADS);
    for (int i=0; i<NUMBER_OF_HANDLER_THREADS; i++){
        all_captured_segments[i] = (char**) malloc(sizeof(char*) * 100);
        for (int j=0; j<100; j++){
            all_captured_segments[i][j] = (char*) malloc(sizeof(char) * MAX_STRING_LEN);
        }
    }
    int** all_captured_ids = (int**) malloc(sizeof(int*) * NUMBER_OF_HANDLER_THREADS);
    for (int i=0; i<NUMBER_OF_HANDLER_THREADS; i++){
        all_captured_ids[i] = (int*) malloc(sizeof(int) * 100);
    }
    HandlerArguments *handler_args_arr[NUMBER_OF_HANDLER_THREADS];
    for (int i=0; i<NUMBER_OF_HANDLER_THREADS; i++){
        handler_args_arr[i] = malloc(sizeof(HandlerArguments));
        handler_args_arr[i]->thread_id = i;
        handler_args_arr[i]->payloads_arr_ptr = payloads_arr;
        handler_args_arr[i]->ids_arr_ptr = ids_arr;
        handler_args_arr[i]->flags_arr_ptr = flags_arr;
        handler_args_arr[i]->reader_done = &reading_done;
        handler_args_arr[i]->read_cnt = all_read_cnts[i];
        handler_args_arr[i]->captured_segments = all_captured_segments[i];
        handler_args_arr[i]->captured_ids = all_captured_ids[i];
        pthread_create(&handler_threads[i], NULL, packet_handler_runner, (void*)handler_args_arr[i]);
    }

    for (int i = 0; i < NUMBER_OF_READER_THREADS; i++) {
        pthread_join(reader_threads[i], NULL);
        // free(args_arr[i]);
    }   

    usleep(10);

    for (int i = 0; i < NUMBER_OF_HANDLER_THREADS; i++) {
        pthread_join(handler_threads[i], NULL);
    }   

    int total_cnt = 0;
    for (int i=0; i<NUMBER_OF_HANDLER_THREADS; i++) {
        total_cnt += *(all_read_cnts[i]);
        printf("thread %d captured :\n", i);
        for (int j=0; j<*(all_read_cnts[i]); j++){
            printf("%s\n", all_captured_segments[i][j]);
        }
        printf("\n");
    }
    printf("total number of signatures found: %d\n", total_cnt);

    int t_idx = 0;
    char** total_segments = (char**) malloc(sizeof(char*) * total_cnt);
    int* total_ids = (int*) malloc(sizeof(int) * total_cnt);
    for (int i=0; i<NUMBER_OF_HANDLER_THREADS; i++){
        for (int j=0; j<*(all_read_cnts[i]); j++){
            total_ids[t_idx] = all_captured_ids[i][j];
            total_segments[t_idx] = (char*) malloc(sizeof(char) * MAX_STRING_LEN);
            strncpy(total_segments[t_idx], all_captured_segments[i][j], MAX_STRING_LEN);
            t_idx ++;
        }
    }

    write_payloads_to_json(total_segments, total_ids, total_cnt, "./temp/output.json");
    printf("writing to json done\n");

    pcap_close(handle);

    // write_segments_to_json(all_segments, total_segments, json_file);

    // free(all_segments);

    // clock_t end_time = clock();
    // double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed_time = (end_time.tv_sec - start_time.tv_sec) + 
                          (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    // printf("Segments extracted and written to %s\n", json_file);
    printf("Total UDP packets: %d\n", udp_packet_count);
    printf("Total segments: %d\n", total_cnt);
    printf("Elapsed time: %.2f seconds\n", elapsed_time);

    printf("done and done\n");
    return 0;
}
