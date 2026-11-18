/*
 * proctrace SQLite interposer.
 *
 * Set PROCTRACE_SQLITE_SOCK to a Unix datagram socket owned by proctrace.
 * Load with DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD (Linux).  We hook
 * sqlite3_open_v2 once and register SQLITE_TRACE_STMT, which gives us the
 * expanded SQL text without touching prepare/step internals.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

typedef int (*open_v2_fn)(const char *, sqlite3 **, int, const char *);
typedef int (*trace_v2_fn)(sqlite3 *, unsigned, int (*)(unsigned, void *, void *, void *), void *);
typedef const char *(*db_filename_fn)(sqlite3 *, const char *);
typedef sqlite3 *(*db_handle_fn)(sqlite3_stmt *);

static open_v2_fn real_open_v2;
static trace_v2_fn real_trace_v2;
static db_filename_fn real_db_filename;
static db_handle_fn real_db_handle;
static pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;
static int sock_fd = -1;

static int shim_open_v2(const char *filename, sqlite3 **db, int flags, const char *vfs);

#ifdef __APPLE__
typedef struct {
    const void *replacement;
    const void *replacee;
} interpose_t;
extern const interpose_t interpose_open_v2;
#endif

static void resolve_symbols(void) {
    if (real_open_v2 && real_trace_v2 && real_db_filename && real_db_handle) return;
#ifdef __APPLE__
    static void *handle = NULL;
    if (!handle) handle = dlopen("/usr/lib/libsqlite3.dylib", RTLD_LAZY | RTLD_LOCAL);
#else
    static void *handle = NULL;
    if (!handle) handle = dlopen("libsqlite3.so.0", RTLD_LAZY | RTLD_LOCAL);
    if (!handle) handle = dlopen("libsqlite3.so", RTLD_LAZY | RTLD_LOCAL);
#endif
    if (!handle) return;
#ifdef __APPLE__
    if (!real_open_v2) real_open_v2 = (open_v2_fn)interpose_open_v2.replacee;
#else
    if (!real_open_v2) real_open_v2 = (open_v2_fn)dlsym(handle, "sqlite3_open_v2");
#endif
    if (!real_trace_v2) real_trace_v2 = (trace_v2_fn)dlsym(handle, "sqlite3_trace_v2");
    if (!real_db_filename) real_db_filename = (db_filename_fn)dlsym(handle, "sqlite3_db_filename");
    if (!real_db_handle) real_db_handle = (db_handle_fn)dlsym(handle, "sqlite3_db_handle");
}

static void json_escape(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    if (!in) in = "";
    for (size_t i = 0; in[i] && j + 8 < out_size; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
            case '"': out[j++] = '\\'; out[j++] = '"'; break;
            case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
            case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
            case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
            case '\t': out[j++] = '\\'; out[j++] = 't'; break;
            default:
                if (c < 0x20) {
                    j += (size_t)snprintf(out + j, out_size - j, "\\u%04x", c);
                } else {
                    out[j++] = (char)c;
                }
        }
    }
    out[j] = '\0';
}

static void send_sql(sqlite3 *db, const char *sql) {
    const char *path = getenv("PROCTRACE_SQLITE_SOCK");
    if (!path || !*path || !sql) return;
    size_t sql_len = strlen(sql);
    /* Keep the datagram/JSON payload within the fixed 32 KiB buffer. */
    if (sql_len > 3000) sql_len = 3000;
    char *raw = (char *)malloc(sql_len + 1);
    if (!raw) return;
    memcpy(raw, sql, sql_len);
    raw[sql_len] = '\0';

    const char *dbname = "";
    if (real_db_filename) {
        const char *value = real_db_filename(db, "main");
        if (value) dbname = value;
    }
    size_t sql_size = sql_len * 6 + 256;
    char *escaped_sql = (char *)malloc(sql_size);
    size_t db_size = strlen(dbname) * 6 + 16;
    char *escaped_db = (char *)malloc(db_size);
    if (!escaped_sql || !escaped_db) {
        free(raw); free(escaped_sql); free(escaped_db); return;
    }
    json_escape(raw, escaped_sql, sql_size);
    json_escape(dbname, escaped_db, db_size);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char payload[32768];
    int n = snprintf(
        payload, sizeof(payload),
        "{\"ts\":%lld.%09ld,\"pid\":%ld,\"db\":\"%s\",\"sql\":\"%s\"}\n",
        (long long)ts.tv_sec, ts.tv_nsec, (long)getpid(), escaped_db, escaped_sql
    );
    free(raw); free(escaped_sql); free(escaped_db);
    if (n <= 0) return;
    if ((size_t)n >= sizeof(payload)) n = (int)sizeof(payload) - 1;

    pthread_mutex_lock(&send_lock);
    if (sock_fd < 0) {
        sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (sock_fd >= 0) {
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
            if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                close(sock_fd);
                sock_fd = -1;
            }
        }
    }
    if (sock_fd >= 0) {
        if (send(sock_fd, payload, (size_t)n, MSG_DONTWAIT) < 0) {
            close(sock_fd);
            sock_fd = -1;
        }
    }
    pthread_mutex_unlock(&send_lock);
}

static int trace_cb(unsigned mask, void *ctx, void *stmt_ptr, void *x) {
    (void)mask;
    (void)ctx;
    if (!x) return 0;
    sqlite3_stmt *stmt = (sqlite3_stmt *)stmt_ptr;
    sqlite3 *db = NULL;
    if (real_db_handle && stmt) db = real_db_handle(stmt);
    send_sql(db, (const char *)x);
    return 0;
}

static int shim_open_v2(const char *filename, sqlite3 **db, int flags, const char *vfs) {
    resolve_symbols();
    if (!real_open_v2) return SQLITE_ERROR;
    int rc = real_open_v2(filename, db, flags, vfs);
    if (rc == SQLITE_OK && db && *db && real_trace_v2) {
        real_trace_v2(*db, SQLITE_TRACE_STMT, trace_cb, NULL);
    }
    return rc;
}

#ifdef __APPLE__
__attribute__((used, section("__DATA,__interpose")))
const interpose_t interpose_open_v2 = {
    (const void *)shim_open_v2, (const void *)sqlite3_open_v2
};
#else
int sqlite3_open_v2(const char *filename, sqlite3 **db, int flags, const char *vfs) {
    return shim_open_v2(filename, db, flags, vfs);
}
#endif
