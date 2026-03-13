#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h> // POSIX threads
#include <sys/socket.h>
#include <arpa/inet.h> // TCP Socket API
#include <netinet/in.h> // TCP Socket API
#include <errno.h>

#define MAX_THREADS 256
#define MAX_PORTS 65535

typedef struct {
    char target[16];
    int start_port;
    int end_port;
    int *open_ports;
    int *count;
    pthread_mutex_t *mutex;
} thread_args;

void *scan_port(void *arg) {
    thread_args *data = (thread_args*)arg;
    int sock;
    struct sockaddr_in addr;

    for (int port = data->start_port; port <= data->end_port; port++) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        // Set up address
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, data->target, &addr.sin_addr) != 1) {
            close(sock);
            continue;
        }
        
        // 4-second timeout so connection doesn't hang forever
        struct timeval tv = { .tv_sec = 4, .tv_usec = 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            pthread_mutex_lock(data->mutex);
            data->open_ports[(*data->count)++] = port;
            pthread_mutex_unlock(data->mutex);
        }
        close(sock);
    }
    return NULL;
}

extern int tcp_connect_scan(const char* target, int start, int end, int** ports_out, int* count_out) {
    pthread_t threads[MAX_THREADS];
    thread_args args[MAX_THREADS];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    int total_ports = end - start + 1;
    if (total_ports <= 0) return -1;
    
    int num_threads = (total_ports > MAX_THREADS) ? MAX_THREADS : total_ports;
    int ports_per_thread = total_ports / num_threads;
    int remainder = total_ports % num_threads;

    // Allocate memory for open ports (worst case is all ports open)
    *ports_out = malloc(total_ports * sizeof(int));
    if (*ports_out == NULL) return -1;
    *count_out = 0;

    // Launch threads
    int current_start = start;
    for (int i = 0; i < num_threads; i++) {
        int chunk = ports_per_thread + (i < remainder ? 1 : 0);
        args[i].start_port = current_start;
        args[i].end_port = current_start + chunk - 1;
        current_start += chunk;

        strncpy(args[i].target, target, sizeof(args[i].target) - 1);
        args[i].target[sizeof(args[i].target) - 1] = '\0';
        args[i].open_ports = *ports_out;
        args[i].count = count_out;
        args[i].mutex = &mutex;

        pthread_create(&threads[i], NULL, scan_port, &args[i]);
    }

    // Wait for all threads to finish
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&mutex);
    return 0; // success
}
