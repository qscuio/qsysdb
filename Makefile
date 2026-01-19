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

# Run tests
.PHONY: test
test: tests
	@echo "Running unit tests..."
	@$(BINDIR)/test_json
	@$(BINDIR)/test_radix
	@echo "All unit tests passed!"

# Run all tests including integration tests
.PHONY: test-all
test-all: tests tests-integration
	@echo "Running all tests..."
	@$(BINDIR)/test_json
	@$(BINDIR)/test_radix
	@$(BINDIR)/test_integration
	@$(BINDIR)/test_socket_unit
	@$(BINDIR)/test_connection
	@echo "All tests passed!"

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
	@echo "Targets:"
	@echo "  all          - Build daemon, library, and CLI (default)"
	@echo "  kernel       - Build kernel module"
	@echo "  tests        - Build test programs"
	@echo "  examples     - Build example programs"
	@echo "  test         - Run all tests"
	@echo "  install      - Install userspace components"
	@echo "  install-kernel - Install kernel module"
	@echo "  clean        - Remove build artifacts"
	@echo "  debug        - Build with debug flags and sanitizers"
	@echo "  format       - Format source code with clang-format"
	@echo "  check        - Run static analysis with cppcheck"
	@echo "  help         - Show this help message"

.PHONY: .FORCE
.FORCE:
