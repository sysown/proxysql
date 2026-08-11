#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <libpq-fe.h>

#define MAX_ITERS 200000

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static double percentile(double *sorted, int n, double p) {
    int idx = (int)(n * p);
    if (idx >= n) idx = n - 1;
    return sorted[idx];
}

struct thread_arg {
    int thread_id;
    char conninfo[1024];
    int iterations;
    int warmup;
    /* results (heap-allocated per thread) */
    double *connect_us;
    double *close_us;
    double *total_us;
    int errors;
};

static void *thread_worker(void *varg) {
    struct thread_arg *arg = varg;
    arg->connect_us = malloc(arg->iterations * sizeof(double));
    arg->close_us   = malloc(arg->iterations * sizeof(double));
    arg->total_us   = malloc(arg->iterations * sizeof(double));
    arg->errors = 0;

    /* Warmup */
    for (int i = 0; i < arg->warmup; i++) {
        PGconn *c = PQconnectdb(arg->conninfo);
        if (PQstatus(c) != CONNECTION_OK) {
            fprintf(stderr, "[thread %d] Warmup connect failed: %s\n",
                    arg->thread_id, PQerrorMessage(c));
            PQfinish(c);
            continue;
        }
        PQfinish(c);
    }

    /* Measurement */
    struct timespec t0, t1, t2;
    for (int i = 0; i < arg->iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        PGconn *c = PQconnectdb(arg->conninfo);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        if (PQstatus(c) != CONNECTION_OK) {
            arg->errors++;
            if (arg->errors <= 3)
                fprintf(stderr, "[thread %d] Connect failed iter %d: %s\n",
                        arg->thread_id, i, PQerrorMessage(c));
            PQfinish(c);
            clock_gettime(CLOCK_MONOTONIC, &t2);
            arg->connect_us[i] = (t1.tv_sec - t0.tv_sec) * 1e6 + (t1.tv_nsec - t0.tv_nsec) / 1e3;
            arg->close_us[i]   = (t2.tv_sec - t1.tv_sec) * 1e6 + (t2.tv_nsec - t1.tv_nsec) / 1e3;
            arg->total_us[i]   = arg->connect_us[i] + arg->close_us[i];
            continue;
        }

        PQfinish(c);
        clock_gettime(CLOCK_MONOTONIC, &t2);

        double ct = (t1.tv_sec - t0.tv_sec) * 1e6 + (t1.tv_nsec - t0.tv_nsec) / 1e3;
        double cl = (t2.tv_sec - t1.tv_sec) * 1e6 + (t2.tv_nsec - t1.tv_nsec) / 1e3;
        arg->connect_us[i] = ct;
        arg->close_us[i]   = cl;
        arg->total_us[i]   = ct + cl;
    }
    return NULL;
}

int main(int argc, char **argv) { // NOSONAR: benchmark tool, cognitive complexity acceptable
    const char *host = "127.0.0.1";
    int port = 16432;
    const char *user = "benchuser"; // NOSONAR: benchmark default, not a real credential
    const char *password = "bench123"; // NOSONAR: benchmark default, not a real credential
    const char *dbname = "pgbouncer";
    const char *ssl_ca = NULL;
    int iterations = 10000;
    int warmup = 200;
    const char *label = "";
    int threads = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i+1 < argc) host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i+1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--user") == 0 && i+1 < argc) user = argv[++i];
        else if (strcmp(argv[i], "--password") == 0 && i+1 < argc) password = argv[++i];
        else if (strcmp(argv[i], "--dbname") == 0 && i+1 < argc) dbname = argv[++i];
        else if (strcmp(argv[i], "--ssl-ca") == 0 && i+1 < argc) ssl_ca = argv[++i];
        else if (strcmp(argv[i], "--iterations") == 0 && i+1 < argc) iterations = atoi(argv[++i]);
        else if (strcmp(argv[i], "--warmup") == 0 && i+1 < argc) warmup = atoi(argv[++i]);
        else if (strcmp(argv[i], "--label") == 0 && i+1 < argc) label = argv[++i];
        else if (strcmp(argv[i], "--threads") == 0 && i+1 < argc) threads = atoi(argv[++i]);
        else { fprintf(stderr, "Unknown arg: %s\n", argv[i]); return 1; }
    }

    if (iterations > MAX_ITERS) {
        fprintf(stderr, "Too many iterations (max %d)\n", MAX_ITERS);
        return 1;
    }

    char conninfo[1024];
    snprintf(conninfo, sizeof(conninfo),
        "host=%s port=%d user=%s password=%s dbname=%s sslmode=require%s%s",
        host, port, user, password, dbname,
        ssl_ca ? " sslrootcert=" : "",
        ssl_ca ? ssl_ca : "");

    /* Launch threads */
    pthread_t *tids = calloc(threads, sizeof(pthread_t));
    struct thread_arg *args = calloc(threads, sizeof(struct thread_arg));
    if (tids == NULL || args == NULL) {
        fprintf(stderr, "Unable to allocate benchmark thread state\n");
        free(tids);
        free(args);
        return 1;
    }

    struct timespec wall0, wall1;
    clock_gettime(CLOCK_MONOTONIC, &wall0);

    for (int t = 0; t < threads; t++) {
        args[t].thread_id = t;
        snprintf(args[t].conninfo, sizeof(args[t].conninfo), "%s", conninfo);
        args[t].iterations = iterations;
        args[t].warmup = warmup;
        pthread_create(&tids[t], NULL, thread_worker, &args[t]);
    }
    for (int t = 0; t < threads; t++)
        pthread_join(tids[t], NULL);

    clock_gettime(CLOCK_MONOTONIC, &wall1);
    double wall_elapsed = (wall1.tv_sec - wall0.tv_sec) + (wall1.tv_nsec - wall0.tv_nsec) / 1e9;

    /* Merge results from all threads */
    int total_n = threads * iterations;
    double *connect_us = malloc(total_n * sizeof(double));
    double *close_us   = malloc(total_n * sizeof(double));
    double *total_us   = malloc(total_n * sizeof(double));
    int total_errors = 0;
    int idx = 0;
    for (int t = 0; t < threads; t++) {
        total_errors += args[t].errors;
        memcpy(connect_us + idx, args[t].connect_us, iterations * sizeof(double));
        memcpy(close_us   + idx, args[t].close_us,   iterations * sizeof(double));
        memcpy(total_us   + idx, args[t].total_us,    iterations * sizeof(double));
        free(args[t].connect_us);
        free(args[t].close_us);
        free(args[t].total_us);
        idx += iterations;
    }
    free(args);
    free(tids);

    int n = total_n;

    /* Compute stats */
    double sum_total = 0;
    for (int i = 0; i < n; i++) sum_total += total_us[i];
    double cps = n / wall_elapsed;

    double *sorted_conn = malloc(n * sizeof(double));
    double *sorted_total = malloc(n * sizeof(double));
    memcpy(sorted_conn, connect_us, n * sizeof(double));
    memcpy(sorted_total, total_us, n * sizeof(double));
    qsort(sorted_conn, n, sizeof(double), cmp_double);
    qsort(sorted_total, n, sizeof(double), cmp_double);

    double avg_conn = 0, avg_close = 0, avg_total = 0;
    for (int i = 0; i < n; i++) {
        avg_conn += connect_us[i];
        avg_close += close_us[i];
        avg_total += total_us[i];
    }
    avg_conn /= n; avg_close /= n; avg_total /= n;

    /* Output human-readable */
    printf("\n============================================================\n");
    printf("  %s\n", label);
    printf("============================================================\n");
    printf("  Threads:         %d\n", threads);
    printf("  Iterations:      %d (per thread: %d)\n", n, iterations);
    printf("  Errors:          %d\n", total_errors);
    printf("  Conns/sec:       %.1f\n", cps);
    printf("  Wall elapsed:    %.3f s\n", wall_elapsed);
    printf("\n");
    printf("  %-12s %10s %10s %10s %10s %10s %10s\n",
           "Metric", "Min", "Avg", "P50", "P90", "P99", "Max");
    printf("  %s\n", "------------------------------------------------------------------------");
    printf("  %-12s %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f\n",
           "Connect", sorted_conn[0], avg_conn,
           percentile(sorted_conn, n, 0.50),
           percentile(sorted_conn, n, 0.90),
           percentile(sorted_conn, n, 0.99),
           sorted_conn[n-1]);
    printf("  %-12s %10.1f %10.1f %10.1f\n",
           "Close", close_us[0], avg_close,
           close_us[n/2]);
    printf("  %-12s %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f\n",
           "Total", sorted_total[0], avg_total,
           percentile(sorted_total, n, 0.50),
           percentile(sorted_total, n, 0.90),
           percentile(sorted_total, n, 0.99),
           sorted_total[n-1]);
    printf("  (all times in microseconds)\n\n");

    /* Output JSON to stderr */
    fprintf(stderr, "{");
    fprintf(stderr, "\"label\":\"%s\",", label);
    fprintf(stderr, "\"threads\":%d,", threads);
    fprintf(stderr, "\"iterations\":%d,", n);
    fprintf(stderr, "\"errors\":%d,", total_errors);
    fprintf(stderr, "\"connections_per_sec\":%.1f,", cps);
    fprintf(stderr, "\"connect_us\":{\"min\":%.1f,\"avg\":%.1f,\"p50\":%.1f,\"p90\":%.1f,\"p99\":%.1f,\"max\":%.1f},",
            sorted_conn[0], avg_conn,
            percentile(sorted_conn, n, 0.50),
            percentile(sorted_conn, n, 0.90),
            percentile(sorted_conn, n, 0.99),
            sorted_conn[n-1]);
    fprintf(stderr, "\"close_us\":{\"min\":%.1f,\"avg\":%.1f,\"p50\":%.1f},",
            close_us[0], avg_close, close_us[n/2]);
    fprintf(stderr, "\"total_us\":{\"min\":%.1f,\"avg\":%.1f,\"p50\":%.1f,\"p90\":%.1f,\"p99\":%.1f,\"max\":%.1f},",
            sorted_total[0], avg_total,
            percentile(sorted_total, n, 0.50),
            percentile(sorted_total, n, 0.90),
            percentile(sorted_total, n, 0.99),
            sorted_total[n-1]);
    fprintf(stderr, "\"elapsed_s\":%.3f", wall_elapsed);
    fprintf(stderr, "}\n");

    free(connect_us); free(close_us); free(total_us);
    free(sorted_conn); free(sorted_total);
    return 0;
}
