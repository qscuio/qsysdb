/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * async.h - Professional async client API for event loop integration
 *
 * This API is designed for easy integration with existing event loops
 * (epoll, libevent, libuv, libev, etc.) and provides:
 *
 * - Non-blocking async operations with callbacks
 * - Event source abstraction for any event loop
 * - Subscription builder with filtering options
 * - Batch operations for efficiency
 * - Clean error handling with result types
 *
 * Example usage with epoll:
 *
 *   // Create client with custom event handling
 *   qsysdb_async_t *client = qsysdb_async_new();
 *   qsysdb_async_connect(client, NULL, 0);
 *
 *   // Get fd for your event loop
 *   int fd = qsysdb_async_fd(client);
 *   epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
 *
 *   // In your event loop when fd is ready:
 *   qsysdb_async_process(client);
 *
 *   // Async set with callback
 *   qsysdb_async_set(client, "/my/path", "{\"value\": 1}",
 *                    on_set_complete, userdata);
 *
 *   // Subscribe with builder pattern
 *   qsysdb_watch(client)
 *       ->pattern("/events/wildcard")
 *       ->on_create(handle_create, NULL)
 *       ->on_update(handle_update, NULL)
 *       ->on_delete(handle_delete, NULL)
 *       ->start();
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#ifndef QSYSDB_ASYNC_H
#define QSYSDB_ASYNC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <qsysdb/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================
 * Opaque Types
 * ============================================ */

/** Async client handle */
typedef struct qsysdb_async qsysdb_async_t;

/** Watch (subscription) handle */
typedef struct qsysdb_watch qsysdb_watch_t;

/** Batch operation handle */
typedef struct qsysdb_batch qsysdb_batch_t;

/** Async operation handle (for cancellation) */
typedef struct qsysdb_op qsysdb_op_t;

/* ============================================
 * Result Types
 * ============================================ */

/**
 * Generic result structure for async operations
 */
typedef struct qsysdb_result {
    int error;                  /* QSYSDB_OK or error code */
    uint64_t version;           /* Entry version (for set/get) */
    uint64_t timestamp;         /* Modification timestamp */
    uint64_t sequence;          /* Global sequence number */
} qsysdb_result_t;

/**
 * Get result with value
 */
typedef struct qsysdb_get_result {
    qsysdb_result_t base;
    const char *value;          /* JSON value (valid until next operation) */
    size_t value_len;
} qsysdb_get_result_t;

/**
 * List result
 */
typedef struct qsysdb_list_result {
    qsysdb_result_t base;
    const char **paths;         /* Array of paths */
    size_t count;
} qsysdb_list_result_t;

/**
 * Batch result
 */
typedef struct qsysdb_batch_result {
    qsysdb_result_t base;
    int succeeded;              /* Number of successful operations */
    int failed;                 /* Number of failed operations */
} qsysdb_batch_result_t;

/**
 * Watch event data
 */
typedef struct qsysdb_event {
    int type;                   /* QSYSDB_EVENT_* */
    const char *path;
    size_t path_len;
    const char *value;          /* JSON value (NULL for delete) */
    size_t value_len;
    uint64_t version;
    uint64_t timestamp;
    uint64_t sequence;
    int subscription_id;
} qsysdb_event_t;

/* ============================================
 * Callback Types
 * ============================================ */

/** Completion callback for simple operations (set, delete, etc.) */
typedef void (*qsysdb_complete_fn)(qsysdb_result_t *result, void *userdata);

/** Completion callback for get operation */
typedef void (*qsysdb_get_fn)(qsysdb_get_result_t *result, void *userdata);

/** Completion callback for list operation */
typedef void (*qsysdb_list_fn)(qsysdb_list_result_t *result, void *userdata);

/** Completion callback for batch operation */
typedef void (*qsysdb_batch_fn)(qsysdb_batch_result_t *result, void *userdata);

/** Watch event handler */
typedef void (*qsysdb_event_fn)(qsysdb_event_t *event, void *userdata);

/** Connection state change handler */
typedef void (*qsysdb_state_fn)(qsysdb_async_t *client, bool connected, void *userdata);

/** Error handler */
typedef void (*qsysdb_error_fn)(qsysdb_async_t *client, int error,
                                 const char *message, void *userdata);

/* ============================================
 * Client Creation and Configuration
 * ============================================ */

/**
 * Create a new async client instance
 *
 * @return  New client handle (must be freed with qsysdb_async_free)
 */
qsysdb_async_t *qsysdb_async_new(void);

/**
 * Free async client and all resources
 *
 * @param client  Client handle
 */
void qsysdb_async_free(qsysdb_async_t *client);

/**
 * Configure connection state change handler
 *
 * Called when connection is established or lost.
 *
 * @param client    Client handle
 * @param handler   State change callback
 * @param userdata  User data for callback
 */
void qsysdb_async_on_state(qsysdb_async_t *client,
                           qsysdb_state_fn handler, void *userdata);

/**
 * Configure error handler
 *
 * Called when errors occur during async operations.
 *
 * @param client    Client handle
 * @param handler   Error callback
 * @param userdata  User data for callback
 */
void qsysdb_async_on_error(qsysdb_async_t *client,
                           qsysdb_error_fn handler, void *userdata);

/**
 * Set reconnect behavior
 *
 * @param client          Client handle
 * @param auto_reconnect  Enable auto-reconnect on disconnect
 * @param interval_ms     Reconnect interval in milliseconds
 */
void qsysdb_async_set_reconnect(qsysdb_async_t *client,
                                 bool auto_reconnect, int interval_ms);

/* ============================================
 * Connection Management
 * ============================================ */

/**
 * Connect to QSysDB daemon (non-blocking)
 *
 * Connection is established asynchronously. Use qsysdb_async_on_state()
 * to get notified when connected.
 *
 * @param client       Client handle
 * @param socket_path  Path to daemon socket (NULL for default)
 * @param flags        Connection flags (QSYSDB_CONN_*)
 * @return             QSYSDB_OK if connect initiated, error otherwise
 */
int qsysdb_async_connect(qsysdb_async_t *client,
                         const char *socket_path, int flags);

/**
 * Connect via TCP (non-blocking)
 *
 * @param client  Client handle
 * @param host    Hostname or IP (NULL for localhost)
 * @param port    Port (0 for default: 5959)
 * @param flags   Connection flags
 * @return        QSYSDB_OK if connect initiated
 */
int qsysdb_async_connect_tcp(qsysdb_async_t *client,
                              const char *host, uint16_t port, int flags);

/**
 * Disconnect from server
 *
 * @param client  Client handle
 */
void qsysdb_async_disconnect(qsysdb_async_t *client);

/**
 * Check if client is connected
 *
 * @param client  Client handle
 * @return        true if connected
 */
bool qsysdb_async_is_connected(qsysdb_async_t *client);

/* ============================================
 * Event Loop Integration
 * ============================================ */

/**
 * Get file descriptor for event loop integration
 *
 * Add this fd to your event loop (epoll, poll, select, etc.)
 * and call qsysdb_async_process() when the fd is readable.
 *
 * @param client  Client handle
 * @return        File descriptor, or -1 if not connected
 */
int qsysdb_async_fd(qsysdb_async_t *client);

/**
 * Get events to wait for (for poll/epoll)
 *
 * Returns a combination of:
 * - QSYSDB_EVENT_READ  (0x01) - Wait for read
 * - QSYSDB_EVENT_WRITE (0x02) - Wait for write
 *
 * @param client  Client handle
 * @return        Event mask
 */
int qsysdb_async_events(qsysdb_async_t *client);

#define QSYSDB_WAIT_READ   0x01
#define QSYSDB_WAIT_WRITE  0x02

/**
 * Process pending I/O and invoke callbacks
 *
 * Call this when your event loop indicates the fd is ready.
 * This will:
 * - Read incoming data
 * - Process responses and invoke completion callbacks
 * - Process notifications and invoke watch handlers
 * - Send pending outgoing data
 *
 * @param client  Client handle
 * @return        Number of callbacks invoked, or negative on error
 */
int qsysdb_async_process(qsysdb_async_t *client);

/**
 * Process with timeout (for simple event loops)
 *
 * Blocks until fd is ready or timeout expires, then processes.
 *
 * @param client      Client handle
 * @param timeout_ms  Timeout (-1 = infinite, 0 = non-blocking)
 * @return            Number of callbacks invoked, or negative on error
 */
int qsysdb_async_poll(qsysdb_async_t *client, int timeout_ms);

/**
 * Run event loop until disconnect or error
 *
 * For simple applications that don't have their own event loop.
 *
 * @param client  Client handle
 * @return        Error code on exit
 */
int qsysdb_async_run(qsysdb_async_t *client);

/**
 * Stop the run loop
 *
 * @param client  Client handle
 */
void qsysdb_async_stop(qsysdb_async_t *client);

/* ============================================
 * Async Operations
 * ============================================ */

/**
 * Set a value asynchronously
 *
 * @param client    Client handle
 * @param path      Path (must start with '/')
 * @param value     JSON value string
 * @param callback  Completion callback (can be NULL)
 * @param userdata  User data for callback
 * @return          Operation handle (for cancellation), or NULL on error
 */
qsysdb_op_t *qsysdb_async_set(qsysdb_async_t *client,
                               const char *path, const char *value,
                               qsysdb_complete_fn callback, void *userdata);

/**
 * Set with options
 *
 * @param client    Client handle
 * @param path      Path
 * @param value     JSON value
 * @param flags     Entry flags (QSYSDB_FLAG_*)
 * @param callback  Completion callback
 * @param userdata  User data
 * @return          Operation handle
 */
qsysdb_op_t *qsysdb_async_set_ex(qsysdb_async_t *client,
                                  const char *path, const char *value,
                                  uint32_t flags,
                                  qsysdb_complete_fn callback, void *userdata);

/**
 * Get a value asynchronously
 *
 * @param client    Client handle
 * @param path      Path to retrieve
 * @param callback  Completion callback (receives value in result)
 * @param userdata  User data for callback
 * @return          Operation handle
 */
qsysdb_op_t *qsysdb_async_get(qsysdb_async_t *client,
                               const char *path,
                               qsysdb_get_fn callback, void *userdata);

/**
 * Delete a value asynchronously
 *
 * @param client    Client handle
 * @param path      Path to delete
 * @param callback  Completion callback
 * @param userdata  User data
 * @return          Operation handle
 */
qsysdb_op_t *qsysdb_async_delete(qsysdb_async_t *client,
                                  const char *path,
                                  qsysdb_complete_fn callback, void *userdata);

/**
 * Check if path exists asynchronously
 *
 * Result will have error = QSYSDB_OK if exists, QSYSDB_ERR_NOTFOUND if not.
 *
 * @param client    Client handle
 * @param path      Path to check
 * @param callback  Completion callback
 * @param userdata  User data
 * @return          Operation handle
 */
qsysdb_op_t *qsysdb_async_exists(qsysdb_async_t *client,
                                  const char *path,
                                  qsysdb_complete_fn callback, void *userdata);

/**
 * List paths under prefix asynchronously
 *
 * @param client    Client handle
 * @param prefix    Path prefix (or "/" for all)
 * @param callback  Completion callback (receives path list)
 * @param userdata  User data
 * @return          Operation handle
 */
qsysdb_op_t *qsysdb_async_list(qsysdb_async_t *client,
                                const char *prefix,
                                qsysdb_list_fn callback, void *userdata);

/**
 * Delete tree under prefix asynchronously
 *
 * @param client    Client handle
 * @param prefix    Path prefix
 * @param callback  Completion callback
 * @param userdata  User data
 * @return          Operation handle
 */
qsysdb_op_t *qsysdb_async_delete_tree(qsysdb_async_t *client,
                                       const char *prefix,
                                       qsysdb_complete_fn callback, void *userdata);

/**
 * Cancel a pending operation
 *
 * The callback will NOT be invoked for cancelled operations.
 *
 * @param op  Operation handle
 */
void qsysdb_op_cancel(qsysdb_op_t *op);

/* ============================================
 * Watch (Subscription) Builder API
 * ============================================ */

/**
 * Create a new watch builder
 *
 * Usage:
 *   qsysdb_watch_t *w = qsysdb_watch_create(client);
 *   qsysdb_watch_pattern(w, "/events/wildcard");
 *   qsysdb_watch_on_event(w, my_handler, userdata);
 *   qsysdb_watch_start(w);
 *
 * @param client  Client handle
 * @return        Watch builder handle
 */
qsysdb_watch_t *qsysdb_watch_create(qsysdb_async_t *client);

/**
 * Set watch pattern
 *
 * Patterns:
 * - "/exact/path"     - Match exact path
 * - "/prefix" + "*"   - Match all paths under prefix (wildcard)
 * - "/prefix" + "**"  - Match recursively under prefix
 *
 * @param watch    Watch handle
 * @param pattern  Path pattern
 * @return         Same watch handle (for chaining)
 */
qsysdb_watch_t *qsysdb_watch_pattern(qsysdb_watch_t *watch, const char *pattern);

/**
 * Set handler for all events
 *
 * @param watch     Watch handle
 * @param handler   Event handler
 * @param userdata  User data for handler
 * @return          Same watch handle (for chaining)
 */
qsysdb_watch_t *qsysdb_watch_on_event(qsysdb_watch_t *watch,
                                       qsysdb_event_fn handler, void *userdata);

/**
 * Set handler for create events only
 *
 * @param watch     Watch handle
 * @param handler   Event handler
 * @param userdata  User data
 * @return          Same watch handle
 */
qsysdb_watch_t *qsysdb_watch_on_create(qsysdb_watch_t *watch,
                                        qsysdb_event_fn handler, void *userdata);

/**
 * Set handler for update events only
 *
 * @param watch     Watch handle
 * @param handler   Event handler
 * @param userdata  User data
 * @return          Same watch handle
 */
qsysdb_watch_t *qsysdb_watch_on_update(qsysdb_watch_t *watch,
                                        qsysdb_event_fn handler, void *userdata);

/**
 * Set handler for delete events only
 *
 * @param watch     Watch handle
 * @param handler   Event handler
 * @param userdata  User data
 * @return          Same watch handle
 */
qsysdb_watch_t *qsysdb_watch_on_delete(qsysdb_watch_t *watch,
                                        qsysdb_event_fn handler, void *userdata);

/**
 * Get initial value when watch starts
 *
 * If enabled, the on_create or on_event handler will be called immediately
 * with the current value after the watch is started.
 *
 * @param watch   Watch handle
 * @param enable  Enable initial value fetch
 * @return        Same watch handle
 */
qsysdb_watch_t *qsysdb_watch_get_initial(qsysdb_watch_t *watch, bool enable);

/**
 * Set event queue size (for backpressure)
 *
 * @param watch       Watch handle
 * @param queue_size  Max queued events (0 = unlimited)
 * @return            Same watch handle
 */
qsysdb_watch_t *qsysdb_watch_queue_size(qsysdb_watch_t *watch, int queue_size);

/**
 * Start the watch
 *
 * @param watch  Watch handle
 * @return       Subscription ID (>0) on success, negative on error
 */
int qsysdb_watch_start(qsysdb_watch_t *watch);

/**
 * Stop and destroy the watch
 *
 * @param watch  Watch handle
 */
void qsysdb_watch_stop(qsysdb_watch_t *watch);

/**
 * Pause watch (stop receiving events temporarily)
 *
 * @param watch  Watch handle
 */
void qsysdb_watch_pause(qsysdb_watch_t *watch);

/**
 * Resume paused watch
 *
 * @param watch  Watch handle
 */
void qsysdb_watch_resume(qsysdb_watch_t *watch);

/* ============================================
 * Batch Operations
 * ============================================ */

/**
 * Create a new batch operation
 *
 * Batch operations are executed atomically on the server.
 *
 * Usage:
 *   qsysdb_batch_t *batch = qsysdb_batch_create(client);
 *   qsysdb_batch_set(batch, "/path1", "{...}");
 *   qsysdb_batch_set(batch, "/path2", "{...}");
 *   qsysdb_batch_delete(batch, "/path3");
 *   qsysdb_batch_execute(batch, callback, userdata);
 *
 * @param client  Client handle
 * @return        Batch handle
 */
qsysdb_batch_t *qsysdb_batch_create(qsysdb_async_t *client);

/**
 * Add set operation to batch
 *
 * @param batch  Batch handle
 * @param path   Path
 * @param value  JSON value
 * @return       Same batch handle (for chaining)
 */
qsysdb_batch_t *qsysdb_batch_set(qsysdb_batch_t *batch,
                                  const char *path, const char *value);

/**
 * Add delete operation to batch
 *
 * @param batch  Batch handle
 * @param path   Path
 * @return       Same batch handle
 */
qsysdb_batch_t *qsysdb_batch_delete(qsysdb_batch_t *batch, const char *path);

/**
 * Get number of operations in batch
 *
 * @param batch  Batch handle
 * @return       Number of operations
 */
int qsysdb_batch_count(qsysdb_batch_t *batch);

/**
 * Execute batch asynchronously
 *
 * @param batch     Batch handle (freed after execution)
 * @param callback  Completion callback
 * @param userdata  User data
 * @return          Operation handle
 */
qsysdb_op_t *qsysdb_batch_execute(qsysdb_batch_t *batch,
                                   qsysdb_batch_fn callback, void *userdata);

/**
 * Cancel and free batch without executing
 *
 * @param batch  Batch handle
 */
void qsysdb_batch_cancel(qsysdb_batch_t *batch);

/* ============================================
 * Synchronous Convenience Functions
 * ============================================ */

/**
 * Synchronous set (blocks until complete)
 *
 * For applications that don't need async, or for simple scripts.
 *
 * @param client  Client handle
 * @param path    Path
 * @param value   JSON value
 * @return        QSYSDB_OK on success
 */
int qsysdb_async_set_sync(qsysdb_async_t *client,
                           const char *path, const char *value);

/**
 * Synchronous get (blocks until complete)
 *
 * @param client  Client handle
 * @param path    Path
 * @param buf     Buffer for value
 * @param buflen  Buffer size
 * @return        QSYSDB_OK on success
 */
int qsysdb_async_get_sync(qsysdb_async_t *client,
                           const char *path, char *buf, size_t buflen);

/**
 * Synchronous delete (blocks until complete)
 *
 * @param client  Client handle
 * @param path    Path
 * @return        QSYSDB_OK on success
 */
int qsysdb_async_delete_sync(qsysdb_async_t *client, const char *path);

/* ============================================
 * Utility Functions
 * ============================================ */

/**
 * Get pending operation count
 *
 * @param client  Client handle
 * @return        Number of operations waiting for response
 */
int qsysdb_async_pending_count(qsysdb_async_t *client);

/**
 * Get active watch count
 *
 * @param client  Client handle
 * @return        Number of active watches
 */
int qsysdb_async_watch_count(qsysdb_async_t *client);

/**
 * Get client statistics
 */
typedef struct qsysdb_client_stats {
    uint64_t ops_sent;          /* Total operations sent */
    uint64_t ops_completed;     /* Total operations completed */
    uint64_t ops_failed;        /* Total operations failed */
    uint64_t events_received;   /* Total events received */
    uint64_t bytes_sent;        /* Total bytes sent */
    uint64_t bytes_received;    /* Total bytes received */
    int pending_ops;            /* Currently pending operations */
    int active_watches;         /* Active subscriptions */
} qsysdb_client_stats_t;

/**
 * Get client statistics
 *
 * @param client  Client handle
 * @param stats   Output statistics
 */
void qsysdb_async_get_stats(qsysdb_async_t *client, qsysdb_client_stats_t *stats);

/* ============================================
 * Convenience Macros
 * ============================================ */

/**
 * Fluent API macros for C (optional)
 *
 * These macros provide a more fluent interface in C:
 *
 *   QSYSDB_WATCH(client, "/events/wildcard")
 *       .on_update(handler, data)
 *       .start();
 */
#ifdef QSYSDB_ENABLE_FLUENT_MACROS

#define QSYSDB_WATCH(client, pat) \
    (*({ \
        qsysdb_watch_t *_w = qsysdb_watch_create(client); \
        qsysdb_watch_pattern(_w, pat); \
        _w; \
    }))

#define QSYSDB_BATCH(client) \
    (*qsysdb_batch_create(client))

#endif /* QSYSDB_ENABLE_FLUENT_MACROS */

#ifdef __cplusplus
}
#endif

/* ============================================
 * C++ Wrapper (optional, header-only)
 * ============================================ */
#ifdef __cplusplus
#ifdef QSYSDB_ENABLE_CXX_WRAPPER

#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace qsysdb {

class Client {
public:
    Client() : handle_(qsysdb_async_new()) {}
    ~Client() { if (handle_) qsysdb_async_free(handle_); }

    // Non-copyable
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // Movable
    Client(Client&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
    Client& operator=(Client&& other) noexcept {
        if (this != &other) {
            if (handle_) qsysdb_async_free(handle_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    // Connection
    int connect(const char* path = nullptr, int flags = 0) {
        return qsysdb_async_connect(handle_, path, flags);
    }

    int connect_tcp(const char* host, uint16_t port, int flags = 0) {
        return qsysdb_async_connect_tcp(handle_, host, port, flags);
    }

    void disconnect() { qsysdb_async_disconnect(handle_); }
    bool is_connected() const { return qsysdb_async_is_connected(handle_); }

    // Event loop integration
    int fd() const { return qsysdb_async_fd(handle_); }
    int events() const { return qsysdb_async_events(handle_); }
    int process() { return qsysdb_async_process(handle_); }
    int poll(int timeout_ms) { return qsysdb_async_poll(handle_, timeout_ms); }

    // Async operations with std::function callbacks
    void set(std::string_view path, std::string_view value,
             std::function<void(qsysdb_result_t*)> callback = nullptr);

    void get(std::string_view path,
             std::function<void(qsysdb_get_result_t*)> callback);

    void del(std::string_view path,
             std::function<void(qsysdb_result_t*)> callback = nullptr);

    // Sync operations
    int set_sync(std::string_view path, std::string_view value) {
        return qsysdb_async_set_sync(handle_,
            std::string(path).c_str(), std::string(value).c_str());
    }

    std::string get_sync(std::string_view path) {
        char buf[65536];
        if (qsysdb_async_get_sync(handle_, std::string(path).c_str(),
                                   buf, sizeof(buf)) == QSYSDB_OK) {
            return std::string(buf);
        }
        return "";
    }

    // Raw handle access
    qsysdb_async_t* handle() { return handle_; }

private:
    qsysdb_async_t* handle_;
};

} // namespace qsysdb

#endif /* QSYSDB_ENABLE_CXX_WRAPPER */
#endif /* __cplusplus */

#endif /* QSYSDB_ASYNC_H */
