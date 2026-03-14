#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_MAX_THREADS 256

typedef struct {
    char target[INET6_ADDRSTRLEN];
    int family;
    int start_port;
    int end_port;
    int timeout_seconds;
    int *open_ports;
    int *count;
    int *progress_counter;
    pthread_mutex_t *mutex;
} thread_args;

static void *scan_port(void *arg) {
    thread_args *data = (thread_args *)arg;

    for (int port = data->start_port; port <= data->end_port; port++) {
        int sock = socket(data->family, SOCK_STREAM, 0);
        if (sock < 0) {
            pthread_mutex_lock(data->mutex);
            (*data->progress_counter)++;
            pthread_mutex_unlock(data->mutex);
            continue;
        }

        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
        socklen_t addr_len = 0;

        if (data->family == AF_INET) {
            struct sockaddr_in *addr4 = (struct sockaddr_in *)&ss;
            addr4->sin_family = AF_INET;
            addr4->sin_port = htons(port);
            if (inet_pton(AF_INET, data->target, &addr4->sin_addr) != 1) {
                close(sock);
                pthread_mutex_lock(data->mutex);
                (*data->progress_counter)++;
                pthread_mutex_unlock(data->mutex);
                continue;
            }
            addr_len = sizeof(struct sockaddr_in);
        } else if (data->family == AF_INET6) {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&ss;
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = htons(port);
            if (inet_pton(AF_INET6, data->target, &addr6->sin6_addr) != 1) {
                close(sock);
                pthread_mutex_lock(data->mutex);
                (*data->progress_counter)++;
                pthread_mutex_unlock(data->mutex);
                continue;
            }
            addr_len = sizeof(struct sockaddr_in6);
        } else {
            close(sock);
            pthread_mutex_lock(data->mutex);
            (*data->progress_counter)++;
            pthread_mutex_unlock(data->mutex);
            continue;
        }

        // Use caller-provided timeout so long scans remain tunable from CLI.
        struct timeval tv = {.tv_sec = data->timeout_seconds, .tv_usec = 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr *)&ss, addr_len) == 0) {
            pthread_mutex_lock(data->mutex);
            data->open_ports[(*data->count)++] = port;
            pthread_mutex_unlock(data->mutex);
        }

        close(sock);

        pthread_mutex_lock(data->mutex);
        (*data->progress_counter)++;
        pthread_mutex_unlock(data->mutex);
    }

    return NULL;
}

extern int tcp_connect_scan(const char *target,
                            int start,
                            int end,
                            int family,
                            int timeout_seconds,
                            int max_threads,
                            int **ports_out,
                            int *count_out,
                            int *progress_counter) {
    if (ports_out == NULL || count_out == NULL || progress_counter == NULL) {
        return -1;
    }

    int total_ports = end - start + 1;
    if (total_ports <= 0 || timeout_seconds < 1 || max_threads < 1) {
        return -1;
    }

    int thread_cap = max_threads;
    if (thread_cap > 1024) {
        thread_cap = 1024;
    }

    int num_threads = (total_ports > thread_cap) ? thread_cap : total_ports;
    if (num_threads <= 0) {
        num_threads = (total_ports > DEFAULT_MAX_THREADS) ? DEFAULT_MAX_THREADS : total_ports;
    }

    pthread_t *threads = calloc((size_t)num_threads, sizeof(pthread_t));
    thread_args *args = calloc((size_t)num_threads, sizeof(thread_args));
    if (threads == NULL || args == NULL) {
        free(threads);
        free(args);
        return -1;
    }

    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    // Allocate memory for open ports (worst case is all ports open).
    *ports_out = malloc((size_t)total_ports * sizeof(int));
    if (*ports_out == NULL) {
        free(threads);
        free(args);
        pthread_mutex_destroy(&mutex);
        return -1;
    }

    *count_out = 0;
    *progress_counter = 0;

    int ports_per_thread = total_ports / num_threads;
    int remainder = total_ports % num_threads;

    int launched = 0;
    int current_start = start;

    for (int i = 0; i < num_threads; i++) {
        int chunk = ports_per_thread + (i < remainder ? 1 : 0);
        args[i].start_port = current_start;
        args[i].end_port = current_start + chunk - 1;
        current_start += chunk;

        strncpy(args[i].target, target, sizeof(args[i].target) - 1);
        args[i].target[sizeof(args[i].target) - 1] = '\0';
        args[i].family = family;
        args[i].timeout_seconds = timeout_seconds;
        args[i].open_ports = *ports_out;
        args[i].count = count_out;
        args[i].progress_counter = progress_counter;
        args[i].mutex = &mutex;

        int create_ret = pthread_create(&threads[i], NULL, scan_port, &args[i]);
        if (create_ret != 0) {
            for (int j = 0; j < i; j++) {
                pthread_join(threads[j], NULL);
            }
            free(*ports_out);
            *ports_out = NULL;
            *count_out = 0;
            *progress_counter = 0;
            pthread_mutex_destroy(&mutex);
            free(threads);
            free(args);
            return -1;
        }

        launched++;
    }

    int join_failed = 0;
    for (int i = 0; i < launched; i++) {
        int rc = pthread_join(threads[i], NULL);
        if (rc != 0 && join_failed == 0) {
            join_failed = rc;
        }
    }

    pthread_mutex_destroy(&mutex);
    free(threads);
    free(args);

    if (join_failed != 0) {
        free(*ports_out);
        *ports_out = NULL;
        *count_out = 0;
        *progress_counter = 0;
        return -1;
    }

    return 0;
}

extern void scanner_free(void *ptr) {
    free(ptr);
}
