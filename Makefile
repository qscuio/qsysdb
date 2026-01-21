# QSysDB - Hierarchical State Database with Kernel Support
# Makefile

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -Werror -O2 -g -fPIC -D_GNU_SOURCE
CFLAGS += -I$(CURDIR)/include -I$(CURDIR)/src
LDFLAGS := -lpthread -lrt

# Directories
SRCDIR := src
INCDIR := include
BUILDDIR := build
BINDIR := bin
LIBDIR := lib
KERNELDIR := kernel
TESTDIR := tests
TOOLSDIR := tools
EXAMPLEDIR := examples

# Kernel build
KDIR ?= /lib/modules/$(shell uname -r)/build
KBUILD_EXTRA_SYMBOLS := $(CURDIR)/kernel/Module.symvers

# Source files
COMMON_SRCS := $(wildcard $(SRCDIR)/common/*.c)
DAEMON_SRCS := $(wildcard $(SRCDIR)/daemon/*.c)
LIB_SRCS := $(wildcard $(SRCDIR)/lib/*.c)
TEST_SRCS := $(wildcard $(TESTDIR)/*.c)
TOOL_SRCS := $(wildcard $(TOOLSDIR)/*.c)
EXAMPLE_SRCS := $(wildcard $(EXAMPLEDIR)/*.c)

# Object files
COMMON_OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(COMMON_SRCS))
DAEMON_OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(DAEMON_SRCS))
DAEMON_OBJS_NO_MAIN := $(filter-out $(BUILDDIR)/daemon/main.o,$(DAEMON_OBJS))
LIB_OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(LIB_SRCS))

# Targets
DAEMON := $(BINDIR)/qsysdbd
STATIC_LIB := $(LIBDIR)/libqsysdb.a
SHARED_LIB := $(LIBDIR)/libqsysdb.so
CLI := $(BINDIR)/qsysdb-cli
TESTS := $(patsubst $(TESTDIR)/%.c,$(BINDIR)/%,$(TEST_SRCS))
EXAMPLES := $(patsubst $(EXAMPLEDIR)/%.c,$(BINDIR)/%,$(filter-out %kernel_agent.c,$(EXAMPLE_SRCS)))

# Default target
.PHONY: all
all: dirs $(DAEMON) $(STATIC_LIB) $(SHARED_LIB) $(CLI)

# Create directories
.PHONY: dirs
dirs:
	@mkdir -p $(BUILDDIR)/common $(BUILDDIR)/daemon $(BUILDDIR)/lib
	@mkdir -p $(BINDIR) $(LIBDIR)

# Compile common objects
$(BUILDDIR)/common/%.o: $(SRCDIR)/common/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile daemon objects
$(BUILDDIR)/daemon/%.o: $(SRCDIR)/daemon/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile library objects
$(BUILDDIR)/lib/%.o: $(SRCDIR)/lib/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Build daemon
$(DAEMON): $(COMMON_OBJS) $(DAEMON_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Build static library
$(STATIC_LIB): $(COMMON_OBJS) $(LIB_OBJS)
	ar rcs $@ $^

# Build shared library
$(SHARED_LIB): $(COMMON_OBJS) $(LIB_OBJS)
	$(CC) -shared $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Build CLI tool
$(CLI): $(TOOLSDIR)/qsysdb-cli.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< -o $@ -L$(LIBDIR) -lqsysdb $(LDFLAGS)

# Build tests (standalone unit tests - no external dependencies)
.PHONY: tests
tests: dirs $(BINDIR)/test_json $(BINDIR)/test_radix

$(BINDIR)/test_json: $(TESTDIR)/test_json.c $(SRCDIR)/common/json.c
	$(CC) $(CFLAGS) $^ -o $@

$(BINDIR)/test_radix: $(TESTDIR)/test_radix.c $(SRCDIR)/common/radix_tree.c
	$(CC) $(CFLAGS) $^ -o $@

# Integration tests (require daemon/library components)
.PHONY: tests-integration
tests-integration: dirs $(COMMON_OBJS) $(DAEMON_OBJS_NO_MAIN) $(LIB_OBJS) \
	$(BINDIR)/test_integration $(BINDIR)/test_connection $(BINDIR)/test_socket_unit

$(BINDIR)/test_integration: $(TESTDIR)/test_integration.c $(COMMON_OBJS) $(DAEMON_OBJS_NO_MAIN)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BINDIR)/test_connection: $(TESTDIR)/test_connection.c $(COMMON_OBJS) $(DAEMON_OBJS_NO_MAIN) $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BINDIR)/test_socket_unit: $(TESTDIR)/test_socket_unit.c $(COMMON_OBJS) $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# ============================================
# Professional Test Framework (New)
# ============================================

# Test framework flags (include test framework headers)
TEST_CFLAGS := $(CFLAGS) -I$(CURDIR)/tests -Wno-unused-function

# New comprehensive unit tests using the test framework
.PHONY: tests-unit
tests-unit: dirs $(COMMON_OBJS) $(DAEMON_OBJS_NO_MAIN) $(LIB_OBJS) \
	$(BINDIR)/test_json_unit $(BINDIR)/test_radix_unit $(BINDIR)/test_database_unit \
	$(BINDIR)/test_multiclient $(BINDIR)/test_network_tables $(BINDIR)/test_async_client \
	$(BINDIR)/test_cluster $(BINDIR)/test_election

$(BINDIR)/test_json_unit: $(TESTDIR)/unit/test_json_unit.c $(SRCDIR)/common/json.c
	$(CC) $(TEST_CFLAGS) $^ -o $@ -lm

$(BINDIR)/test_radix_unit: $(TESTDIR)/unit/test_radix_unit.c $(SRCDIR)/common/radix_tree.c
	$(CC) $(TEST_CFLAGS) $^ -o $@ -lm

$(BINDIR)/test_database_unit: $(TESTDIR)/unit/test_database_unit.c $(COMMON_OBJS) $(DAEMON_OBJS_NO_MAIN)
	$(CC) $(TEST_CFLAGS) $^ -o $@ $(LDFLAGS) -lm

$(BINDIR)/test_multiclient: $(TESTDIR)/unit/test_multiclient.c $(COMMON_OBJS) $(DAEMON_OBJS_NO_MAIN)
	$(CC) $(TEST_CFLAGS) $^ -o $@ $(LDFLAGS) -lm

$(BINDIR)/test_network_tables: $(TESTDIR)/unit/test_network_tables.c $(COMMON_OBJS) $(DAEMON_OBJS_NO_MAIN)
	$(CC) $(TEST_CFLAGS) $^ -o $@ $(LDFLAGS) -lm

$(BINDIR)/test_async_client: $(TESTDIR)/unit/test_async_client.c $(COMMON_OBJS) $(LIB_OBJS)
	$(CC) $(TEST_CFLAGS) $^ -o $@ $(LDFLAGS) -lm

$(BINDIR)/test_cluster: $(TESTDIR)/unit/test_cluster.c $(COMMON_OBJS) $(DAEMON_OBJS_NO_MAIN)
	$(CC) $(TEST_CFLAGS) $^ -o $@ $(LDFLAGS) -lm

$(BINDIR)/test_election: $(TESTDIR)/unit/test_election.c $(COMMON_OBJS) $(DAEMON_OBJS_NO_MAIN)
	$(CC) $(TEST_CFLAGS) $^ -o $@ $(LDFLAGS) -lm

# Benchmark tests
.PHONY: bench
bench: dirs $(COMMON_OBJS) $(DAEMON_OBJS_NO_MAIN) $(LIB_OBJS) $(BINDIR)/bench_all $(BINDIR)/bench_async_client

$(BINDIR)/bench_all: $(TESTDIR)/bench/bench_all.c $(COMMON_OBJS) $(DAEMON_OBJS_NO_MAIN)
	$(CC) $(TEST_CFLAGS) $^ -o $@ $(LDFLAGS) -lm

$(BINDIR)/bench_async_client: $(TESTDIR)/bench/bench_async_client.c $(COMMON_OBJS) $(LIB_OBJS)
	$(CC) $(TEST_CFLAGS) $^ -o $@ $(LDFLAGS) -lm

# Run new unit tests
.PHONY: test-unit
test-unit: tests-unit
	@echo ""
	@echo "Running comprehensive unit tests..."
	@echo ""
	@$(BINDIR)/test_json_unit
	@$(BINDIR)/test_radix_unit
	@$(BINDIR)/test_database_unit
	@$(BINDIR)/test_multiclient
	@$(BINDIR)/test_network_tables
	@$(BINDIR)/test_async_client
	@$(BINDIR)/test_cluster
	@$(BINDIR)/test_election

# Run benchmarks
.PHONY: benchmark
benchmark: bench
	@echo ""
	@echo "Running benchmarks..."
	@echo ""
	@$(BINDIR)/bench_all
	@$(BINDIR)/bench_async_client

# Run benchmarks with verbose output
.PHONY: benchmark-verbose
benchmark-verbose: bench
	@echo ""
	@echo "Running benchmarks (verbose)..."
	@echo ""
	@$(BINDIR)/bench_all -v
	@$(BINDIR)/bench_async_client -v

# Run benchmarks and save results to CSV
.PHONY: benchmark-csv
benchmark-csv: bench
	@mkdir -p results
	@$(BINDIR)/bench_all --csv results/benchmark_$(shell date +%Y%m%d_%H%M%S).csv
	@echo "Results saved to results/"

# Run benchmarks and save results to JSON
.PHONY: benchmark-json
benchmark-json: bench
	@mkdir -p results
	@$(BINDIR)/bench_all --json results/benchmark_$(shell date +%Y%m%d_%H%M%S).json
	@echo "Results saved to results/"

# ============================================
# Legacy test targets (kept for compatibility)
# ============================================

# Run tests
.PHONY: test
test: tests
	@echo "Running unit tests..."
	@$(BINDIR)/test_json
	@$(BINDIR)/test_radix
	@echo "All unit tests passed!"

# Run all tests including integration tests
.PHONY: test-all
test-all: tests tests-integration tests-unit
	@echo "Running all tests..."
	@$(BINDIR)/test_json
	@$(BINDIR)/test_radix
	@$(BINDIR)/test_integration
	@$(BINDIR)/test_socket_unit
	@$(BINDIR)/test_connection
	@echo ""
	@echo "Running comprehensive unit tests..."
	@$(BINDIR)/test_json_unit
	@$(BINDIR)/test_radix_unit
	@$(BINDIR)/test_database_unit
	@$(BINDIR)/test_multiclient
	@$(BINDIR)/test_network_tables
	@echo ""
	@echo "All tests passed!"

# Run full test suite with benchmarks
.PHONY: test-full
test-full: test-all benchmark
	@echo ""
	@echo "Full test suite completed!"

# Build examples
.PHONY: examples
examples: dirs $(EXAMPLES)

$(BINDIR)/%: $(EXAMPLEDIR)/%.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< -o $@ -L$(LIBDIR) -lqsysdb $(LDFLAGS)

# Build kernel module
.PHONY: kernel
kernel:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/$(KERNELDIR) modules

.PHONY: kernel-clean
kernel-clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/$(KERNELDIR) clean

# Install
.PHONY: install
install: all
	install -d $(DESTDIR)/usr/local/bin
	install -d $(DESTDIR)/usr/local/lib
	install -d $(DESTDIR)/usr/local/include/qsysdb
	install -d $(DESTDIR)/var/run/qsysdb
	install -m 755 $(DAEMON) $(DESTDIR)/usr/local/bin/
	install -m 755 $(CLI) $(DESTDIR)/usr/local/bin/
	install -m 644 $(STATIC_LIB) $(DESTDIR)/usr/local/lib/
	install -m 755 $(SHARED_LIB) $(DESTDIR)/usr/local/lib/
	install -m 644 $(INCDIR)/qsysdb/*.h $(DESTDIR)/usr/local/include/qsysdb/
	ldconfig || true

.PHONY: install-kernel
install-kernel: kernel
	$(MAKE) -C $(KDIR) M=$(CURDIR)/$(KERNELDIR) modules_install
	depmod -a

# Clean
.PHONY: clean
clean:
	rm -rf $(BUILDDIR) $(BINDIR) $(LIBDIR)
	rm -f $(KERNELDIR)/*.o $(KERNELDIR)/*.ko $(KERNELDIR)/*.mod*
	rm -f $(KERNELDIR)/Module.symvers $(KERNELDIR)/modules.order
	rm -rf $(KERNELDIR)/.*.cmd $(KERNELDIR)/.tmp_versions

# Format code
.PHONY: format
format:
	find $(SRCDIR) $(INCDIR) $(TESTDIR) $(TOOLSDIR) $(EXAMPLEDIR) \
		-name '*.c' -o -name '*.h' | xargs clang-format -i

# Static analysis
.PHONY: check
check:
	cppcheck --enable=all --suppress=missingIncludeSystem \
		$(SRCDIR) $(INCDIR) $(TESTDIR)

# Debug build
.PHONY: debug
debug: CFLAGS += -DDEBUG -O0 -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: all

# Help
.PHONY: help
help:
	@echo "QSysDB Build System"
	@echo ""
	@echo "Build Targets:"
	@echo "  all              - Build daemon, library, and CLI (default)"
	@echo "  kernel           - Build kernel module"
	@echo "  tests            - Build legacy test programs"
	@echo "  tests-unit       - Build comprehensive unit tests (new framework)"
	@echo "  bench            - Build benchmark suite"
	@echo "  examples         - Build example programs"
	@echo ""
	@echo "Test Targets:"
	@echo "  test             - Run legacy unit tests"
	@echo "  test-unit        - Run comprehensive unit tests (new framework)"
	@echo "  test-all         - Run all tests (legacy + comprehensive)"
	@echo "  test-full        - Run all tests + benchmarks"
	@echo ""
	@echo "Benchmark Targets:"
	@echo "  benchmark        - Run benchmark suite"
	@echo "  benchmark-verbose - Run benchmarks with detailed stats"
	@echo "  benchmark-csv    - Run benchmarks and save to CSV"
	@echo "  benchmark-json   - Run benchmarks and save to JSON"
	@echo ""
	@echo "Install Targets:"
	@echo "  install          - Install userspace components"
	@echo "  install-kernel   - Install kernel module"
	@echo ""
	@echo "Other Targets:"
	@echo "  clean            - Remove build artifacts"
	@echo "  debug            - Build with debug flags and sanitizers"
	@echo "  format           - Format source code with clang-format"
	@echo "  check            - Run static analysis with cppcheck"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Test Framework Features:"
	@echo "  - Rich assertions with detailed error messages"
	@echo "  - Test filtering: ./bin/test_json_unit -f pattern"
	@echo "  - Colored output with timing information"
	@echo "  - Benchmark statistics: min/max/mean/stddev/ops-per-sec"

.PHONY: .FORCE
.FORCE:
