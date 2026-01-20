/*
 * QSysDB - Professional Benchmark Framework
 *
 * A lightweight benchmarking framework for C projects.
 * Features:
 *   - Automatic warmup runs
 *   - Statistical analysis (min, max, mean, std dev, percentiles)
 *   - Operations per second calculation
 *   - Memory tracking
 *   - Comparison between runs
 *   - CSV and JSON output
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_BENCHMARK_H
#define QSYSDB_BENCHMARK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <sys/resource.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Configuration
 */
#define BENCH_MAX_BENCHMARKS    256
#define BENCH_MAX_NAME_LEN      128
#define BENCH_MAX_SAMPLES       10000
#define BENCH_DEFAULT_WARMUP    3
#define BENCH_DEFAULT_ITERS     50
#define BENCH_MIN_TIME_MS       50.0    /* Minimum time per benchmark */

/*
 * Color codes
 */
#define BENCH_COLOR_RESET   "\033[0m"
#define BENCH_COLOR_GREEN   "\033[32m"
#define BENCH_COLOR_YELLOW  "\033[33m"
#define BENCH_COLOR_BLUE    "\033[34m"
#define BENCH_COLOR_CYAN    "\033[36m"
#define BENCH_COLOR_BOLD    "\033[1m"
#define BENCH_COLOR_DIM     "\033[2m"

/*
 * Time unit enumeration
 */
typedef enum {
    BENCH_UNIT_AUTO = 0,
    BENCH_UNIT_NS,
    BENCH_UNIT_US,
    BENCH_UNIT_MS,
    BENCH_UNIT_S
} bench_unit_t;

/*
 * Benchmark function types
 */
typedef void (*bench_func_t)(void *userdata);
typedef void (*bench_setup_t)(void *userdata);
typedef void (*bench_teardown_t)(void *userdata);

/*
 * Benchmark statistics
 */
typedef struct bench_stats {
    double min_ns;
    double max_ns;
    double mean_ns;
    double std_dev_ns;
    double median_ns;
    double p95_ns;
    double p99_ns;
    double total_ns;
    uint64_t iterations;
    double ops_per_sec;
    size_t memory_used;
} bench_stats_t;

/*
 * Benchmark definition
 */
typedef struct bench_def {
    char name[BENCH_MAX_NAME_LEN];
    char group[BENCH_MAX_NAME_LEN];
    bench_func_t func;
    bench_setup_t setup;
    bench_teardown_t teardown;
    void *userdata;
    int warmup_iters;
    int min_iters;
    double min_time_ms;
    bool enabled;
} bench_def_t;

/*
 * Benchmark result
 */
typedef struct bench_result {
    char name[BENCH_MAX_NAME_LEN];
    char group[BENCH_MAX_NAME_LEN];
    bench_stats_t stats;
    double *samples;
    int sample_count;
} bench_result_t;

/*
 * Benchmark context
 */
typedef struct bench_context {
    bench_def_t benchmarks[BENCH_MAX_BENCHMARKS];
    bench_result_t results[BENCH_MAX_BENCHMARKS];
    int benchmark_count;
    int result_count;

    /* Configuration */
    bool use_colors;
    bool verbose;
    const char *filter;
    bench_unit_t time_unit;
    FILE *output;
    FILE *csv_output;
    FILE *json_output;

    /* Current state */
    const char *current_name;
    double *current_samples;
    int current_sample_count;
} bench_context_t;

/* Global context */
static bench_context_t g_bench_ctx = {0};

/*
 * High-resolution timing
 */
static inline uint64_t bench_get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline double bench_ns_to_ms(double ns) {
    return ns / 1000000.0;
}

static inline bool bench_should_use_colors(void) {
    const char *no_color = getenv("NO_COLOR");
    if (no_color) return false;
    if (!isatty(STDOUT_FILENO)) return false;
    return true;
}

static inline const char *bench_color(const char *color) {
    return g_bench_ctx.use_colors ? color : "";
}

/*
 * Memory tracking
 */
static inline size_t bench_get_memory_usage(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return (size_t)usage.ru_maxrss * 1024;  /* Convert KB to bytes */
    }
    return 0;
}

/*
 * Statistical helper: compare for qsort
 */
static int bench_compare_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

/*
 * Calculate statistics from samples
 */
static inline void bench_calc_stats(double *samples, int count, bench_stats_t *stats) {
    if (count == 0) {
        memset(stats, 0, sizeof(bench_stats_t));
        return;
    }

    /* Sort samples for percentiles */
    qsort(samples, count, sizeof(double), bench_compare_double);

    stats->min_ns = samples[0];
    stats->max_ns = samples[count - 1];
    stats->median_ns = samples[count / 2];
    stats->p95_ns = samples[(int)(count * 0.95)];
    stats->p99_ns = samples[(int)(count * 0.99)];

    /* Calculate mean */
    double sum = 0;
    for (int i = 0; i < count; i++) {
        sum += samples[i];
    }
    stats->mean_ns = sum / count;
    stats->total_ns = sum;

    /* Calculate standard deviation */
    double variance_sum = 0;
    for (int i = 0; i < count; i++) {
        double diff = samples[i] - stats->mean_ns;
        variance_sum += diff * diff;
    }
    stats->std_dev_ns = sqrt(variance_sum / count);

    stats->iterations = count;
    stats->ops_per_sec = 1000000000.0 / stats->mean_ns;
}

/*
 * Format time value with appropriate unit
 */
static inline const char *bench_format_time(double ns, char *buf, size_t buflen) {
    bench_unit_t unit = g_bench_ctx.time_unit;

    if (unit == BENCH_UNIT_AUTO) {
        if (ns >= 1000000000.0) {
            unit = BENCH_UNIT_S;
        } else if (ns >= 1000000.0) {
            unit = BENCH_UNIT_MS;
        } else if (ns >= 1000.0) {
            unit = BENCH_UNIT_US;
        } else {
            unit = BENCH_UNIT_NS;
        }
    }

    switch (unit) {
    case BENCH_UNIT_S:
        snprintf(buf, buflen, "%.3f s", ns / 1000000000.0);
        break;
    case BENCH_UNIT_MS:
        snprintf(buf, buflen, "%.3f ms", ns / 1000000.0);
        break;
    case BENCH_UNIT_US:
        snprintf(buf, buflen, "%.3f us", ns / 1000.0);
        break;
    case BENCH_UNIT_NS:
    default:
        snprintf(buf, buflen, "%.1f ns", ns);
        break;
    case BENCH_UNIT_AUTO:
        break;  /* Handled above */
    }

    return buf;
}

/*
 * Format operations per second
 */
static inline const char *bench_format_ops(double ops, char *buf, size_t buflen) {
    if (ops >= 1000000000.0) {
        snprintf(buf, buflen, "%.2f G ops/s", ops / 1000000000.0);
    } else if (ops >= 1000000.0) {
        snprintf(buf, buflen, "%.2f M ops/s", ops / 1000000.0);
    } else if (ops >= 1000.0) {
        snprintf(buf, buflen, "%.2f K ops/s", ops / 1000.0);
    } else {
        snprintf(buf, buflen, "%.2f ops/s", ops);
    }
    return buf;
}

/*
 * Register a benchmark
 */
static inline int bench_register(const char *group, const char *name, bench_func_t func) {
    if (g_bench_ctx.benchmark_count >= BENCH_MAX_BENCHMARKS) {
        fprintf(stderr, "Error: Too many benchmarks registered\n");
        return -1;
    }

    bench_def_t *bench = &g_bench_ctx.benchmarks[g_bench_ctx.benchmark_count++];
    snprintf(bench->name, BENCH_MAX_NAME_LEN, "%s", name);
    snprintf(bench->group, BENCH_MAX_NAME_LEN, "%s", group);
    bench->func = func;
    bench->setup = NULL;
    bench->teardown = NULL;
    bench->userdata = NULL;
    bench->warmup_iters = BENCH_DEFAULT_WARMUP;
    bench->min_iters = BENCH_DEFAULT_ITERS;
    bench->min_time_ms = BENCH_MIN_TIME_MS;
    bench->enabled = true;

    return g_bench_ctx.benchmark_count - 1;
}

/*
 * Register with setup/teardown
 */
static inline int bench_register_full(const char *group, const char *name,
                                       bench_func_t func,
                                       bench_setup_t setup,
                                       bench_teardown_t teardown,
                                       void *userdata) {
    int idx = bench_register(group, name, func);
    if (idx >= 0) {
        g_bench_ctx.benchmarks[idx].setup = setup;
        g_bench_ctx.benchmarks[idx].teardown = teardown;
        g_bench_ctx.benchmarks[idx].userdata = userdata;
    }
    return idx;
}

/*
 * Check if benchmark matches filter
 */
static inline bool bench_matches_filter(const char *name) {
    if (!g_bench_ctx.filter || !g_bench_ctx.filter[0]) return true;
    return strstr(name, g_bench_ctx.filter) != NULL;
}

/*
 * Run a single benchmark
 */
static inline void bench_run_single(bench_def_t *bench, bench_result_t *result) {
    FILE *out = g_bench_ctx.output ? g_bench_ctx.output : stdout;

    snprintf(result->name, BENCH_MAX_NAME_LEN, "%s", bench->name);
    snprintf(result->group, BENCH_MAX_NAME_LEN, "%s", bench->group);

    /* Allocate sample storage */
    result->samples = malloc(BENCH_MAX_SAMPLES * sizeof(double));
    if (!result->samples) {
        fprintf(stderr, "Error: Failed to allocate sample storage\n");
        return;
    }
    result->sample_count = 0;

    /* Warmup runs */
    if (g_bench_ctx.verbose) {
        fprintf(out, "  Warming up (%d iterations)...\n", bench->warmup_iters);
    }
    for (int i = 0; i < bench->warmup_iters; i++) {
        if (bench->setup) bench->setup(bench->userdata);
        bench->func(bench->userdata);
        if (bench->teardown) bench->teardown(bench->userdata);
    }

    /* Actual benchmark runs */
    double min_time_ns = bench->min_time_ms * 1000000.0;
    double total_time = 0;
    int iter = 0;

    while ((total_time < min_time_ns || iter < bench->min_iters) &&
           result->sample_count < BENCH_MAX_SAMPLES) {

        if (bench->setup) bench->setup(bench->userdata);

        uint64_t start = bench_get_time_ns();
        bench->func(bench->userdata);
        uint64_t end = bench_get_time_ns();

        if (bench->teardown) bench->teardown(bench->userdata);

        double elapsed = (double)(end - start);
        result->samples[result->sample_count++] = elapsed;
        total_time += elapsed;
        iter++;
    }

    /* Calculate statistics */
    bench_calc_stats(result->samples, result->sample_count, &result->stats);
    result->stats.memory_used = bench_get_memory_usage();
}

/*
 * Print benchmark result
 */
static inline void bench_print_result(bench_result_t *result) {
    FILE *out = g_bench_ctx.output ? g_bench_ctx.output : stdout;
    char time_buf[64], ops_buf[64];

    fprintf(out, "  %-40s %s%12s%s  %s%16s%s",
            result->name,
            bench_color(BENCH_COLOR_CYAN),
            bench_format_time(result->stats.mean_ns, time_buf, sizeof(time_buf)),
            bench_color(BENCH_COLOR_RESET),
            bench_color(BENCH_COLOR_GREEN),
            bench_format_ops(result->stats.ops_per_sec, ops_buf, sizeof(ops_buf)),
            bench_color(BENCH_COLOR_RESET));

    if (g_bench_ctx.verbose) {
        char min_buf[64], max_buf[64], std_buf[64];
        fprintf(out, "\n    %smin: %s, max: %s, std: %s, samples: %lu%s",
                bench_color(BENCH_COLOR_DIM),
                bench_format_time(result->stats.min_ns, min_buf, sizeof(min_buf)),
                bench_format_time(result->stats.max_ns, max_buf, sizeof(max_buf)),
                bench_format_time(result->stats.std_dev_ns, std_buf, sizeof(std_buf)),
                result->stats.iterations,
                bench_color(BENCH_COLOR_RESET));
    }

    fprintf(out, "\n");
}

/*
 * Write CSV output
 */
static inline void bench_write_csv_header(FILE *f) {
    fprintf(f, "group,name,mean_ns,min_ns,max_ns,std_dev_ns,median_ns,p95_ns,p99_ns,ops_per_sec,iterations\n");
}

static inline void bench_write_csv_result(FILE *f, bench_result_t *result) {
    fprintf(f, "%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%lu\n",
            result->group, result->name,
            result->stats.mean_ns, result->stats.min_ns, result->stats.max_ns,
            result->stats.std_dev_ns, result->stats.median_ns,
            result->stats.p95_ns, result->stats.p99_ns,
            result->stats.ops_per_sec, result->stats.iterations);
}

/*
 * Write JSON output
 */
static inline void bench_write_json_start(FILE *f) {
    fprintf(f, "{\n  \"benchmarks\": [\n");
}

static inline void bench_write_json_result(FILE *f, bench_result_t *result, bool last) {
    fprintf(f, "    {\n");
    fprintf(f, "      \"group\": \"%s\",\n", result->group);
    fprintf(f, "      \"name\": \"%s\",\n", result->name);
    fprintf(f, "      \"mean_ns\": %.2f,\n", result->stats.mean_ns);
    fprintf(f, "      \"min_ns\": %.2f,\n", result->stats.min_ns);
    fprintf(f, "      \"max_ns\": %.2f,\n", result->stats.max_ns);
    fprintf(f, "      \"std_dev_ns\": %.2f,\n", result->stats.std_dev_ns);
    fprintf(f, "      \"median_ns\": %.2f,\n", result->stats.median_ns);
    fprintf(f, "      \"p95_ns\": %.2f,\n", result->stats.p95_ns);
    fprintf(f, "      \"p99_ns\": %.2f,\n", result->stats.p99_ns);
    fprintf(f, "      \"ops_per_sec\": %.2f,\n", result->stats.ops_per_sec);
    fprintf(f, "      \"iterations\": %lu\n", result->stats.iterations);
    fprintf(f, "    }%s\n", last ? "" : ",");
}

static inline void bench_write_json_end(FILE *f) {
    fprintf(f, "  ]\n}\n");
}

/*
 * Run all benchmarks
 */
static inline int bench_run_all(void) {
    FILE *out = g_bench_ctx.output ? g_bench_ctx.output : stdout;

    g_bench_ctx.use_colors = bench_should_use_colors();

    fprintf(out, "\n%s%s=======================================%s\n",
            bench_color(BENCH_COLOR_BOLD), bench_color(BENCH_COLOR_CYAN), bench_color(BENCH_COLOR_RESET));
    fprintf(out, "%s   QSysDB Benchmark Suite%s\n",
            bench_color(BENCH_COLOR_BOLD), bench_color(BENCH_COLOR_RESET));
    fprintf(out, "%s%s=======================================%s\n\n",
            bench_color(BENCH_COLOR_BOLD), bench_color(BENCH_COLOR_CYAN), bench_color(BENCH_COLOR_RESET));

    if (g_bench_ctx.filter && g_bench_ctx.filter[0]) {
        fprintf(out, "Filter: %s\n\n", g_bench_ctx.filter);
    }

    /* CSV header */
    if (g_bench_ctx.csv_output) {
        bench_write_csv_header(g_bench_ctx.csv_output);
    }

    /* JSON start */
    if (g_bench_ctx.json_output) {
        bench_write_json_start(g_bench_ctx.json_output);
    }

    const char *current_group = NULL;
    int run_count = 0;

    for (int i = 0; i < g_bench_ctx.benchmark_count; i++) {
        bench_def_t *bench = &g_bench_ctx.benchmarks[i];

        if (!bench->enabled) continue;

        char full_name[BENCH_MAX_NAME_LEN * 2];
        snprintf(full_name, sizeof(full_name), "%s::%s", bench->group, bench->name);
        if (!bench_matches_filter(full_name) && !bench_matches_filter(bench->name)) {
            continue;
        }

        /* Print group header */
        if (!current_group || strcmp(current_group, bench->group) != 0) {
            current_group = bench->group;
            fprintf(out, "\n%s[%s]%s\n",
                    bench_color(BENCH_COLOR_BOLD), current_group, bench_color(BENCH_COLOR_RESET));
        }

        /* Run benchmark */
        bench_result_t *result = &g_bench_ctx.results[g_bench_ctx.result_count++];
        bench_run_single(bench, result);
        bench_print_result(result);

        /* Write outputs */
        if (g_bench_ctx.csv_output) {
            bench_write_csv_result(g_bench_ctx.csv_output, result);
        }

        run_count++;
    }

    /* JSON end - need to write results */
    if (g_bench_ctx.json_output) {
        for (int i = 0; i < g_bench_ctx.result_count; i++) {
            bench_write_json_result(g_bench_ctx.json_output,
                                    &g_bench_ctx.results[i],
                                    i == g_bench_ctx.result_count - 1);
        }
        bench_write_json_end(g_bench_ctx.json_output);
    }

    /* Summary */
    fprintf(out, "\n%s%s=======================================%s\n",
            bench_color(BENCH_COLOR_BOLD), bench_color(BENCH_COLOR_CYAN), bench_color(BENCH_COLOR_RESET));
    fprintf(out, "%sBenchmark Summary:%s\n", bench_color(BENCH_COLOR_BOLD), bench_color(BENCH_COLOR_RESET));
    fprintf(out, "  Total benchmarks: %d\n", run_count);
    fprintf(out, "%s%s=======================================%s\n\n",
            bench_color(BENCH_COLOR_BOLD), bench_color(BENCH_COLOR_CYAN), bench_color(BENCH_COLOR_RESET));

    /* Cleanup */
    for (int i = 0; i < g_bench_ctx.result_count; i++) {
        free(g_bench_ctx.results[i].samples);
        g_bench_ctx.results[i].samples = NULL;
    }

    return 0;
}

/*
 * Configuration functions
 */
static inline void bench_set_filter(const char *filter) {
    g_bench_ctx.filter = filter;
}

static inline void bench_set_verbose(bool verbose) {
    g_bench_ctx.verbose = verbose;
}

static inline void bench_set_output(FILE *output) {
    g_bench_ctx.output = output;
}

static inline void bench_set_csv_output(FILE *csv) {
    g_bench_ctx.csv_output = csv;
}

static inline void bench_set_json_output(FILE *json) {
    g_bench_ctx.json_output = json;
}

static inline void bench_set_time_unit(bench_unit_t unit) {
    g_bench_ctx.time_unit = unit;
}

/*
 * Benchmark definition macros
 */
#define BENCHMARK(group, name) \
    static void bench_##group##_##name(void *userdata); \
    __attribute__((constructor)) static void _register_bench_##group##_##name(void) { \
        bench_register(#group, #name, bench_##group##_##name); \
    } \
    static void bench_##group##_##name(void *userdata __attribute__((unused)))

#define BENCHMARK_F(group, name, setup_fn, teardown_fn, udata) \
    static void bench_##group##_##name(void *userdata); \
    __attribute__((constructor)) static void _register_bench_##group##_##name(void) { \
        bench_register_full(#group, #name, bench_##group##_##name, setup_fn, teardown_fn, udata); \
    } \
    static void bench_##group##_##name(void *userdata __attribute__((unused)))

/*
 * Iteration helper for benchmarks
 */
#define BENCH_ITER(n) for (int _bench_i = 0; _bench_i < (n); _bench_i++)

/*
 * Prevent compiler optimization of benchmark code
 */
#define BENCH_DO_NOT_OPTIMIZE(x) \
    do { __asm__ __volatile__("" : "+r"(x)); } while (0)

#define BENCH_CLOBBER() \
    do { __asm__ __volatile__("" : : : "memory"); } while (0)

/*
 * Main entry point macro
 */
#define BENCHMARK_MAIN() \
    int main(int argc, char **argv) { \
        for (int i = 1; i < argc; i++) { \
            if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) { \
                bench_set_filter(argv[++i]); \
            } else if (strcmp(argv[i], "-v") == 0) { \
                bench_set_verbose(true); \
            } else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) { \
                FILE *f = fopen(argv[++i], "w"); \
                if (f) bench_set_csv_output(f); \
            } else if (strcmp(argv[i], "--json") == 0 && i + 1 < argc) { \
                FILE *f = fopen(argv[++i], "w"); \
                if (f) bench_set_json_output(f); \
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { \
                printf("Usage: %s [-f filter] [-v] [--csv file] [--json file] [-h]\n", argv[0]); \
                printf("  -f filter   Run only benchmarks matching filter\n"); \
                printf("  -v          Verbose output with statistics\n"); \
                printf("  --csv file  Write results to CSV file\n"); \
                printf("  --json file Write results to JSON file\n"); \
                printf("  -h          Show this help\n"); \
                return 0; \
            } else { \
                bench_set_filter(argv[i]); \
            } \
        } \
        int ret = bench_run_all(); \
        if (g_bench_ctx.csv_output) fclose(g_bench_ctx.csv_output); \
        if (g_bench_ctx.json_output) fclose(g_bench_ctx.json_output); \
        return ret; \
    }

#ifdef __cplusplus
}
#endif

#endif /* QSYSDB_BENCHMARK_H */
