/*
 * QSysDB - Professional Test Framework
 *
 * A lightweight, feature-rich test framework for C projects.
 * Features:
 *   - Test suites with setup/teardown
 *   - Rich assertions with descriptive messages
 *   - Test filtering by name pattern
 *   - Colored output with timing
 *   - Automatic test registration
 *   - Skip and expected failure support
 *   - Memory tracking integration
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_TEST_FRAMEWORK_H
#define QSYSDB_TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <math.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Configuration
 */
#define TEST_MAX_TESTS          1024
#define TEST_MAX_SUITES         64
#define TEST_MAX_NAME_LEN       128
#define TEST_MAX_MESSAGE_LEN    512

/*
 * Color codes for terminal output
 */
#define TEST_COLOR_RESET    "\033[0m"
#define TEST_COLOR_RED      "\033[31m"
#define TEST_COLOR_GREEN    "\033[32m"
#define TEST_COLOR_YELLOW   "\033[33m"
#define TEST_COLOR_BLUE     "\033[34m"
#define TEST_COLOR_MAGENTA  "\033[35m"
#define TEST_COLOR_CYAN     "\033[36m"
#define TEST_COLOR_BOLD     "\033[1m"
#define TEST_COLOR_DIM      "\033[2m"

/*
 * Test result codes
 */
typedef enum {
    TEST_RESULT_PASS = 0,
    TEST_RESULT_FAIL,
    TEST_RESULT_SKIP,
    TEST_RESULT_ERROR,
    TEST_RESULT_TIMEOUT
} test_result_t;

/*
 * Test function types
 */
typedef void (*test_func_t)(void);
typedef void (*test_setup_t)(void);
typedef void (*test_teardown_t)(void);

/*
 * Test case structure
 */
typedef struct test_case {
    char name[TEST_MAX_NAME_LEN];
    char suite[TEST_MAX_NAME_LEN];
    test_func_t func;
    test_setup_t setup;
    test_teardown_t teardown;
    bool skip;
    bool expect_fail;
    const char *skip_reason;
    int timeout_ms;
} test_case_t;

/*
 * Test suite structure
 */
typedef struct test_suite {
    char name[TEST_MAX_NAME_LEN];
    test_setup_t setup;
    test_teardown_t teardown;
    test_setup_t suite_setup;
    test_teardown_t suite_teardown;
    int test_count;
} test_suite_t;

/*
 * Test statistics
 */
typedef struct test_stats {
    int total;
    int passed;
    int failed;
    int skipped;
    int errors;
    double total_time_ms;
} test_stats_t;

/*
 * Global test context
 */
typedef struct test_context {
    test_case_t tests[TEST_MAX_TESTS];
    test_suite_t suites[TEST_MAX_SUITES];
    int test_count;
    int suite_count;

    /* Current test state */
    const char *current_test;
    const char *current_suite;
    test_result_t current_result;
    char current_message[TEST_MAX_MESSAGE_LEN];
    int current_line;
    const char *current_file;

    /* Runtime state */
    jmp_buf jump_buffer;
    bool use_colors;
    bool verbose;
    const char *filter;
    FILE *output;

    /* Statistics */
    test_stats_t stats;
} test_context_t;

/* Global context instance */
static test_context_t g_test_ctx = {0};

/*
 * Internal helper functions
 */
static inline double test_get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static inline bool test_should_use_colors(void) {
    const char *term = getenv("TERM");
    const char *no_color = getenv("NO_COLOR");
    if (no_color) return false;
    if (!isatty(STDOUT_FILENO)) return false;
    if (!term) return false;
    return true;
}

static inline const char *test_color(const char *color) {
    return g_test_ctx.use_colors ? color : "";
}

static inline void test_print_result(test_result_t result, double time_ms) {
    FILE *out = g_test_ctx.output ? g_test_ctx.output : stdout;

    switch (result) {
    case TEST_RESULT_PASS:
        fprintf(out, "%s[PASS]%s", test_color(TEST_COLOR_GREEN), test_color(TEST_COLOR_RESET));
        break;
    case TEST_RESULT_FAIL:
        fprintf(out, "%s[FAIL]%s", test_color(TEST_COLOR_RED), test_color(TEST_COLOR_RESET));
        break;
    case TEST_RESULT_SKIP:
        fprintf(out, "%s[SKIP]%s", test_color(TEST_COLOR_YELLOW), test_color(TEST_COLOR_RESET));
        break;
    case TEST_RESULT_ERROR:
        fprintf(out, "%s[ERROR]%s", test_color(TEST_COLOR_MAGENTA), test_color(TEST_COLOR_RESET));
        break;
    case TEST_RESULT_TIMEOUT:
        fprintf(out, "%s[TIMEOUT]%s", test_color(TEST_COLOR_RED), test_color(TEST_COLOR_RESET));
        break;
    }

    fprintf(out, " %s(%.2f ms)%s", test_color(TEST_COLOR_DIM), time_ms, test_color(TEST_COLOR_RESET));
}

static inline bool test_matches_filter(const char *name) {
    if (!g_test_ctx.filter || !g_test_ctx.filter[0]) return true;
    return strstr(name, g_test_ctx.filter) != NULL;
}

/*
 * Test registration functions
 */
static inline int test_register(const char *suite, const char *name, test_func_t func) {
    if (g_test_ctx.test_count >= TEST_MAX_TESTS) {
        fprintf(stderr, "Error: Too many tests registered (max %d)\n", TEST_MAX_TESTS);
        return -1;
    }

    test_case_t *test = &g_test_ctx.tests[g_test_ctx.test_count++];
    snprintf(test->name, TEST_MAX_NAME_LEN, "%s", name);
    snprintf(test->suite, TEST_MAX_NAME_LEN, "%s", suite);
    test->func = func;
    test->setup = NULL;
    test->teardown = NULL;
    test->skip = false;
    test->expect_fail = false;
    test->skip_reason = NULL;
    test->timeout_ms = 30000;  /* Default 30s timeout */

    return g_test_ctx.test_count - 1;
}

static inline int test_suite_register(const char *name, test_setup_t setup, test_teardown_t teardown) {
    if (g_test_ctx.suite_count >= TEST_MAX_SUITES) {
        fprintf(stderr, "Error: Too many suites registered (max %d)\n", TEST_MAX_SUITES);
        return -1;
    }

    test_suite_t *suite = &g_test_ctx.suites[g_test_ctx.suite_count++];
    snprintf(suite->name, TEST_MAX_NAME_LEN, "%s", name);
    suite->setup = setup;
    suite->teardown = teardown;
    suite->suite_setup = NULL;
    suite->suite_teardown = NULL;
    suite->test_count = 0;

    return g_test_ctx.suite_count - 1;
}

static inline test_suite_t *test_find_suite(const char *name) {
    for (int i = 0; i < g_test_ctx.suite_count; i++) {
        if (strcmp(g_test_ctx.suites[i].name, name) == 0) {
            return &g_test_ctx.suites[i];
        }
    }
    return NULL;
}

/*
 * Assertion failure handler
 */
static inline void test_fail_impl(const char *file, int line, const char *fmt, ...) {
    g_test_ctx.current_result = TEST_RESULT_FAIL;
    g_test_ctx.current_file = file;
    g_test_ctx.current_line = line;

    va_list args;
    va_start(args, fmt);
    vsnprintf(g_test_ctx.current_message, TEST_MAX_MESSAGE_LEN, fmt, args);
    va_end(args);

    longjmp(g_test_ctx.jump_buffer, 1);
}

/*
 * Assertion macros
 */
#define TEST_FAIL(fmt, ...) \
    test_fail_impl(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        TEST_FAIL("Assertion failed: %s", #cond); \
    } \
} while(0)

#define TEST_ASSERT_MSG(cond, fmt, ...) do { \
    if (!(cond)) { \
        TEST_FAIL(fmt, ##__VA_ARGS__); \
    } \
} while(0)

#define TEST_ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        TEST_FAIL("Expected true, got false: %s", #expr); \
    } \
} while(0)

#define TEST_ASSERT_FALSE(expr) do { \
    if ((expr)) { \
        TEST_FAIL("Expected false, got true: %s", #expr); \
    } \
} while(0)

#define TEST_ASSERT_NULL(ptr) do { \
    if ((ptr) != NULL) { \
        TEST_FAIL("Expected NULL, got %p: %s", (void*)(ptr), #ptr); \
    } \
} while(0)

#define TEST_ASSERT_NOT_NULL(ptr) do { \
    if ((ptr) == NULL) { \
        TEST_FAIL("Expected non-NULL: %s", #ptr); \
    } \
} while(0)

#define TEST_ASSERT_EQ(expected, actual) do { \
    long long _exp = (long long)(expected); \
    long long _act = (long long)(actual); \
    if (_exp != _act) { \
        TEST_FAIL("Expected %lld, got %lld: %s == %s", _exp, _act, #expected, #actual); \
    } \
} while(0)

#define TEST_ASSERT_NE(expected, actual) do { \
    long long _exp = (long long)(expected); \
    long long _act = (long long)(actual); \
    if (_exp == _act) { \
        TEST_FAIL("Expected not equal to %lld: %s != %s", _exp, #expected, #actual); \
    } \
} while(0)

#define TEST_ASSERT_LT(a, b) do { \
    long long _a = (long long)(a); \
    long long _b = (long long)(b); \
    if (!(_a < _b)) { \
        TEST_FAIL("Expected %lld < %lld: %s < %s", _a, _b, #a, #b); \
    } \
} while(0)

#define TEST_ASSERT_LE(a, b) do { \
    long long _a = (long long)(a); \
    long long _b = (long long)(b); \
    if (!(_a <= _b)) { \
        TEST_FAIL("Expected %lld <= %lld: %s <= %s", _a, _b, #a, #b); \
    } \
} while(0)

#define TEST_ASSERT_GT(a, b) do { \
    long long _a = (long long)(a); \
    long long _b = (long long)(b); \
    if (!(_a > _b)) { \
        TEST_FAIL("Expected %lld > %lld: %s > %s", _a, _b, #a, #b); \
    } \
} while(0)

#define TEST_ASSERT_GE(a, b) do { \
    long long _a = (long long)(a); \
    long long _b = (long long)(b); \
    if (!(_a >= _b)) { \
        TEST_FAIL("Expected %lld >= %lld: %s >= %s", _a, _b, #a, #b); \
    } \
} while(0)

#define TEST_ASSERT_FLOAT_EQ(expected, actual, epsilon) do { \
    double _exp = (double)(expected); \
    double _act = (double)(actual); \
    double _eps = (double)(epsilon); \
    if (fabs(_exp - _act) > _eps) { \
        TEST_FAIL("Expected %.6f, got %.6f (epsilon %.6f): %s == %s", \
                  _exp, _act, _eps, #expected, #actual); \
    } \
} while(0)

#define TEST_ASSERT_STR_EQ(expected, actual) do { \
    const char *_exp = (expected); \
    const char *_act = (actual); \
    if (_exp == NULL && _act == NULL) break; \
    if (_exp == NULL || _act == NULL || strcmp(_exp, _act) != 0) { \
        TEST_FAIL("Expected \"%s\", got \"%s\": %s == %s", \
                  _exp ? _exp : "(null)", _act ? _act : "(null)", #expected, #actual); \
    } \
} while(0)

#define TEST_ASSERT_STR_NE(expected, actual) do { \
    const char *_exp = (expected); \
    const char *_act = (actual); \
    if (_exp == NULL && _act == NULL) { \
        TEST_FAIL("Both strings are NULL: %s != %s", #expected, #actual); \
    } \
    if (_exp != NULL && _act != NULL && strcmp(_exp, _act) == 0) { \
        TEST_FAIL("Expected strings to differ: \"%s\"", _exp); \
    } \
} while(0)

#define TEST_ASSERT_STR_CONTAINS(haystack, needle) do { \
    const char *_h = (haystack); \
    const char *_n = (needle); \
    if (_h == NULL || _n == NULL || strstr(_h, _n) == NULL) { \
        TEST_FAIL("Expected \"%s\" to contain \"%s\"", \
                  _h ? _h : "(null)", _n ? _n : "(null)"); \
    } \
} while(0)

#define TEST_ASSERT_MEM_EQ(expected, actual, size) do { \
    const void *_exp = (expected); \
    const void *_act = (actual); \
    size_t _size = (size); \
    if (memcmp(_exp, _act, _size) != 0) { \
        TEST_FAIL("Memory comparison failed for %zu bytes: %s == %s", \
                  _size, #expected, #actual); \
    } \
} while(0)

#define TEST_ASSERT_OK(expr) do { \
    int _ret = (expr); \
    if (_ret != QSYSDB_OK) { \
        TEST_FAIL("Expected QSYSDB_OK (0), got %d: %s", _ret, #expr); \
    } \
} while(0)

#define TEST_ASSERT_ERR(expr, expected_err) do { \
    int _ret = (expr); \
    int _expected = (expected_err); \
    if (_ret != _expected) { \
        TEST_FAIL("Expected error %d, got %d: %s", _expected, _ret, #expr); \
    } \
} while(0)

#define TEST_ASSERT_FAILS(expr) do { \
    int _ret = (expr); \
    if (_ret == QSYSDB_OK) { \
        TEST_FAIL("Expected failure, got QSYSDB_OK: %s", #expr); \
    } \
} while(0)

/*
 * Skip test
 */
#define TEST_SKIP(reason) do { \
    g_test_ctx.current_result = TEST_RESULT_SKIP; \
    snprintf(g_test_ctx.current_message, TEST_MAX_MESSAGE_LEN, "%s", reason); \
    longjmp(g_test_ctx.jump_buffer, 1); \
} while(0)

/*
 * Test definition macros
 */
#define TEST_SUITE(name) \
    static const char *_current_suite_name = #name

#define TEST_SETUP(func) \
    static void func(void)

#define TEST_TEARDOWN(func) \
    static void func(void)

#define TEST(name) \
    static void test_##name(void); \
    __attribute__((constructor)) static void _register_##name(void) { \
        test_register(_current_suite_name ? _current_suite_name : "default", #name, test_##name); \
    } \
    static void test_##name(void)

#define TEST_F(suite, name) \
    static void test_##suite##_##name(void); \
    __attribute__((constructor)) static void _register_##suite##_##name(void) { \
        int idx = test_register(#suite, #name, test_##suite##_##name); \
        test_suite_t *s = test_find_suite(#suite); \
        if (s) { \
            g_test_ctx.tests[idx].setup = s->setup; \
            g_test_ctx.tests[idx].teardown = s->teardown; \
        } \
    } \
    static void test_##suite##_##name(void)

/*
 * Suite setup/teardown registration
 */
#define TEST_SUITE_SETUP(suite, setup_func, teardown_func) \
    __attribute__((constructor)) static void _register_suite_##suite(void) { \
        test_suite_register(#suite, setup_func, teardown_func); \
    }

/*
 * Run a single test case
 */
static inline test_result_t test_run_single(test_case_t *test) {
    g_test_ctx.current_test = test->name;
    g_test_ctx.current_suite = test->suite;
    g_test_ctx.current_result = TEST_RESULT_PASS;
    g_test_ctx.current_message[0] = '\0';

    if (test->skip) {
        g_test_ctx.current_result = TEST_RESULT_SKIP;
        if (test->skip_reason) {
            snprintf(g_test_ctx.current_message, TEST_MAX_MESSAGE_LEN, "%s", test->skip_reason);
        }
        return TEST_RESULT_SKIP;
    }

    /* Run setup if present */
    if (test->setup) {
        if (setjmp(g_test_ctx.jump_buffer) != 0) {
            return TEST_RESULT_ERROR;
        }
        test->setup();
    }

    /* Run the test */
    if (setjmp(g_test_ctx.jump_buffer) == 0) {
        test->func();
    }

    /* Handle expected failures */
    if (test->expect_fail) {
        if (g_test_ctx.current_result == TEST_RESULT_FAIL) {
            g_test_ctx.current_result = TEST_RESULT_PASS;
        } else if (g_test_ctx.current_result == TEST_RESULT_PASS) {
            g_test_ctx.current_result = TEST_RESULT_FAIL;
            snprintf(g_test_ctx.current_message, TEST_MAX_MESSAGE_LEN,
                     "Expected test to fail, but it passed");
        }
    }

    /* Run teardown if present */
    if (test->teardown) {
        if (setjmp(g_test_ctx.jump_buffer) != 0) {
            /* Teardown failed, but don't override test result if it was already a failure */
            if (g_test_ctx.current_result == TEST_RESULT_PASS) {
                g_test_ctx.current_result = TEST_RESULT_ERROR;
            }
        } else {
            test->teardown();
        }
    }

    return g_test_ctx.current_result;
}

/*
 * Run all tests
 */
static inline int test_run_all(void) {
    FILE *out = g_test_ctx.output ? g_test_ctx.output : stdout;

    g_test_ctx.use_colors = test_should_use_colors();

    fprintf(out, "\n%s%s=======================================%s\n",
            test_color(TEST_COLOR_BOLD), test_color(TEST_COLOR_CYAN), test_color(TEST_COLOR_RESET));
    fprintf(out, "%s   QSysDB Test Framework%s\n",
            test_color(TEST_COLOR_BOLD), test_color(TEST_COLOR_RESET));
    fprintf(out, "%s%s=======================================%s\n\n",
            test_color(TEST_COLOR_BOLD), test_color(TEST_COLOR_CYAN), test_color(TEST_COLOR_RESET));

    if (g_test_ctx.filter && g_test_ctx.filter[0]) {
        fprintf(out, "Filter: %s\n\n", g_test_ctx.filter);
    }

    memset(&g_test_ctx.stats, 0, sizeof(test_stats_t));

    double total_start = test_get_time_ms();

    const char *current_suite = NULL;

    for (int i = 0; i < g_test_ctx.test_count; i++) {
        test_case_t *test = &g_test_ctx.tests[i];

        /* Check filter */
        char full_name[TEST_MAX_NAME_LEN * 2];
        snprintf(full_name, sizeof(full_name), "%s::%s", test->suite, test->name);
        if (!test_matches_filter(full_name) && !test_matches_filter(test->name)) {
            continue;
        }

        /* Print suite header if changed */
        if (!current_suite || strcmp(current_suite, test->suite) != 0) {
            current_suite = test->suite;
            fprintf(out, "\n%s[Suite: %s]%s\n",
                    test_color(TEST_COLOR_BOLD), current_suite, test_color(TEST_COLOR_RESET));
        }

        fprintf(out, "  %-50s ", test->name);
        fflush(out);

        double start = test_get_time_ms();
        test_result_t result = test_run_single(test);
        double elapsed = test_get_time_ms() - start;

        test_print_result(result, elapsed);

        g_test_ctx.stats.total++;

        switch (result) {
        case TEST_RESULT_PASS:
            g_test_ctx.stats.passed++;
            fprintf(out, "\n");
            break;
        case TEST_RESULT_FAIL:
            g_test_ctx.stats.failed++;
            fprintf(out, "\n");
            fprintf(out, "    %s%s:%d: %s%s\n",
                    test_color(TEST_COLOR_RED),
                    g_test_ctx.current_file ? g_test_ctx.current_file : "unknown",
                    g_test_ctx.current_line,
                    g_test_ctx.current_message,
                    test_color(TEST_COLOR_RESET));
            break;
        case TEST_RESULT_SKIP:
            g_test_ctx.stats.skipped++;
            if (g_test_ctx.current_message[0]) {
                fprintf(out, " %s(%s)%s\n",
                        test_color(TEST_COLOR_DIM),
                        g_test_ctx.current_message,
                        test_color(TEST_COLOR_RESET));
            } else {
                fprintf(out, "\n");
            }
            break;
        case TEST_RESULT_ERROR:
        case TEST_RESULT_TIMEOUT:
            g_test_ctx.stats.errors++;
            fprintf(out, "\n");
            if (g_test_ctx.current_message[0]) {
                fprintf(out, "    %s%s%s\n",
                        test_color(TEST_COLOR_MAGENTA),
                        g_test_ctx.current_message,
                        test_color(TEST_COLOR_RESET));
            }
            break;
        }
    }

    g_test_ctx.stats.total_time_ms = test_get_time_ms() - total_start;

    /* Print summary */
    fprintf(out, "\n%s%s=======================================%s\n",
            test_color(TEST_COLOR_BOLD), test_color(TEST_COLOR_CYAN), test_color(TEST_COLOR_RESET));
    fprintf(out, "%sTest Summary:%s\n", test_color(TEST_COLOR_BOLD), test_color(TEST_COLOR_RESET));
    fprintf(out, "  Total:   %d\n", g_test_ctx.stats.total);
    fprintf(out, "  %sPassed:  %d%s\n",
            g_test_ctx.stats.passed > 0 ? test_color(TEST_COLOR_GREEN) : "",
            g_test_ctx.stats.passed,
            test_color(TEST_COLOR_RESET));
    if (g_test_ctx.stats.failed > 0) {
        fprintf(out, "  %sFailed:  %d%s\n",
                test_color(TEST_COLOR_RED), g_test_ctx.stats.failed, test_color(TEST_COLOR_RESET));
    }
    if (g_test_ctx.stats.skipped > 0) {
        fprintf(out, "  %sSkipped: %d%s\n",
                test_color(TEST_COLOR_YELLOW), g_test_ctx.stats.skipped, test_color(TEST_COLOR_RESET));
    }
    if (g_test_ctx.stats.errors > 0) {
        fprintf(out, "  %sErrors:  %d%s\n",
                test_color(TEST_COLOR_MAGENTA), g_test_ctx.stats.errors, test_color(TEST_COLOR_RESET));
    }
    fprintf(out, "  Time:    %.2f ms\n", g_test_ctx.stats.total_time_ms);
    fprintf(out, "%s%s=======================================%s\n\n",
            test_color(TEST_COLOR_BOLD), test_color(TEST_COLOR_CYAN), test_color(TEST_COLOR_RESET));

    if (g_test_ctx.stats.failed == 0 && g_test_ctx.stats.errors == 0) {
        fprintf(out, "%s%sAll tests passed!%s\n\n",
                test_color(TEST_COLOR_BOLD), test_color(TEST_COLOR_GREEN), test_color(TEST_COLOR_RESET));
        return 0;
    } else {
        fprintf(out, "%s%sSome tests failed!%s\n\n",
                test_color(TEST_COLOR_BOLD), test_color(TEST_COLOR_RED), test_color(TEST_COLOR_RESET));
        return 1;
    }
}

/*
 * Configure the test runner
 */
static inline void test_set_filter(const char *filter) {
    g_test_ctx.filter = filter;
}

static inline void test_set_verbose(bool verbose) {
    g_test_ctx.verbose = verbose;
}

static inline void test_set_output(FILE *output) {
    g_test_ctx.output = output;
}

/*
 * Main entry point macro
 */
#define TEST_MAIN() \
    int main(int argc, char **argv) { \
        for (int i = 1; i < argc; i++) { \
            if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) { \
                test_set_filter(argv[++i]); \
            } else if (strcmp(argv[i], "-v") == 0) { \
                test_set_verbose(true); \
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { \
                printf("Usage: %s [-f filter] [-v] [-h]\n", argv[0]); \
                printf("  -f filter  Run only tests matching filter\n"); \
                printf("  -v         Verbose output\n"); \
                printf("  -h         Show this help\n"); \
                return 0; \
            } else { \
                test_set_filter(argv[i]); \
            } \
        } \
        return test_run_all(); \
    }

#ifdef __cplusplus
}
#endif

#endif /* QSYSDB_TEST_FRAMEWORK_H */
