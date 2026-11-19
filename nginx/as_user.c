/*
 * as_user.c — run a small set of filesystem operations with a mapped unix
 * user's effective credentials, then restore the worker's identity.
 *
 * nginx workers run as root (real uid 0, see nginx/conf.d/default.conf) or,
 * in the planned future deployment, as a non-root user that holds the
 * CAP_SETUID/CAP_SETGID capabilities in its effective set (e.g. via file
 * capabilities on the binary: setcap cap_setuid,cap_setgid+ep). A request
 * authenticated by a remote token may need to create/read files as the
 * mapped user so that POSIX ownership, permissions and quotas apply.
 * Only the open/metadata syscalls need the user's identity: Linux checks
 * DAC at open() time, and read()/write() on an already-open fd are not
 * re-checked, so the worker can stream data over the returned fd without
 * being switched.
 *
 * Safety invariants (critical for use from nginx):
 *  - Every exported function is one straight-line C sequence:
 *    validate -> setegid -> seteuid -> one syscall -> seteuid(worker) ->
 *    setegid(worker) -> return. It never allocates, sleeps or re-enters any
 *    event loop, so a LuaJIT coroutine cannot yield while the worker
 *    process holds switched credentials (the worker multiplexes many
 *    concurrent requests; a yield mid-switch would make other requests'
 *    file I/O run as the wrong user).
 *  - Only *effective* credentials (seteuid/setegid) are switched, and
 *    they are always restored: the worker's real uid/gid stay at their
 *    startup values for its whole lifetime, so there is no way to be
 *    "stuck" as a mapped user.
 *  - The worker must have a clean identity (uid == euid, gid == egid) and
 *    CAP_SETUID and CAP_SETGID in the effective set; root satisfies the
 *    second condition trivially, a non-root worker gets them via file
 *    capabilities (verified empirically: the effective cap set survives
 *    seteuid() between non-zero uids while the caps remain in the
 *    permitted set, so repeated switch/restore round-trips keep working).
 *    Otherwise every call fails with EPERM.
 *  - All paths must be under the configured storage root, and a ".." path
 *    segment is rejected (defense in depth; the Lua layer also validates
 *    the URI before calling here).
 *  - Return convention (like a raw syscall): success values on success
 *    (fd >= 0, or 0), or the negated errno (-errno < 0) on failure. This
 *    avoids reading the process-global errno from Lua: the OpenResty
 *    LuaJIT build's ffi.errno property is unreliable (verified: it returns
 *    a builtin function, not the errno value).
 *
 * Build (x86_64, part of the image build):
 *   gcc -O2 -Wall -Wextra -shared -fPIC -o as_user.so as_user.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h> /* rename(2) */
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* The worker's own identity, captured once on the first switch. nginx
 * workers are single-threaded (one event loop per process) and each worker
 * gets its own copy of this library, so the lazy statics need no locking.
 */
static int worker_uid = -1;
static int worker_gid = -1;

/* capability(7): the kernel's in-kernel representation (CAP_VERSION_3,
 * two 32-bit words covering CAP_0..CAP_63). */
#define CAP_VER3 0x20080522
#define CAP_SETGID_BIT (1u << 6)
#define CAP_SETUID_BIT (1u << 7)
struct cap_hdr_t { int version; int pid; };
struct cap_data_t { unsigned int effective, permitted, inheritable; };

static int have_switch_caps(void) {
    struct cap_hdr_t h = { CAP_VER3, 0 };
    struct cap_data_t d[2] = {{0, 0, 0}, {0, 0, 0}};
    if (syscall(SYS_capget, &h, d) != 0) {
        return 0;
    }
    return (d[0].effective & CAP_SETGID_BIT) != 0 &&
           (d[0].effective & CAP_SETUID_BIT) != 0;
}

/*
 * Switch effective credentials to (uid, gid).
 *
 * Works for a root worker (all caps effective) and for a non-root worker
 * that holds CAP_SETUID/CAP_SETGID in the effective set (file capabilities
 * on the binary; verified on Linux 6.x). Ordering matters: setegid first,
 * because once euid is switched the CAP_SETGID check no longer applies
 * when restoring the gid. Restoring to the real uid/gid is unprivileged,
 * so the restore cannot be blocked even if the effective cap set were
 * somehow lost mid-sequence.
 */
static int as_user_switch(int uid, int gid) {
    if (getuid() != geteuid() || getgid() != getegid()) {
        return -EPERM; /* credentials already switched: cannot happen */
    }
    if (worker_uid < 0) {
        if (!have_switch_caps()) {
            return -EPERM;
        }
        worker_uid = getuid();
        worker_gid = getgid();
    }
    if (setegid((gid_t)gid) != 0) {
        return -EPERM;
    }
    if (seteuid((uid_t)uid) != 0) {
        setegid((gid_t)worker_gid);
        return -EPERM;
    }
    return 0;
}

static void as_user_restore(void) {
    seteuid((uid_t)worker_uid);
    setegid((gid_t)worker_gid);
}

/*
 * True if `path` equals `root` or starts with `root/` and contains no ".."
 * path segment below root.
 */
static int as_user_valid_path(const char *root, const char *path) {
    size_t rlen = strlen(root);
    if (strncmp(path, root, rlen) != 0) {
        return 0;
    }
    if (path[rlen] != '/' && path[rlen] != '\0') {
        return 0;
    }
    /* Reject ".." as a path segment anywhere below root. "..." or "..x"
     * are legitimate names and are allowed. */
    const char *p = path + rlen;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' && (p[2] == '\0' || p[2] == '/')) {
            return 0;
        }
        p++;
    }
    return 1;
}

int as_user_open(int uid, int gid, const char *root, const char *path,
                 int flags, int mode) {
    if (!as_user_valid_path(root, path)) {
        return -EPERM;
    }
    int switched = as_user_switch(uid, gid);
    if (switched != 0) {
        return switched;
    }
    int fd = open(path, flags, (mode_t)mode);
    int saved = errno;
    as_user_restore();
    if (fd < 0) {
        return -saved;
    }
    return fd;
}

int as_user_unlink(int uid, int gid, const char *root, const char *path) {
    if (!as_user_valid_path(root, path)) {
        return -EPERM;
    }
    int switched = as_user_switch(uid, gid);
    if (switched != 0) {
        return switched;
    }
    int rc = unlink(path);
    int saved = errno;
    as_user_restore();
    if (rc != 0) {
        return -saved;
    }
    return 0;
}

int as_user_rename(int uid, int gid, const char *root,
                   const char *src, const char *dst) {
    if (!as_user_valid_path(root, src) || !as_user_valid_path(root, dst)) {
        return -EPERM;
    }
    int switched = as_user_switch(uid, gid);
    if (switched != 0) {
        return switched;
    }
    int rc = rename(src, dst);
    int saved = errno;
    as_user_restore();
    if (rc != 0) {
        return -saved;
    }
    return 0;
}

/*
 * Recursively create all missing parent directories of `path` (then `path`
 * itself) as the mapped user. mkdir(2) returns EEXIST for a directory that
 * already exists; that is not an error here (concurrent writers).
 */
int as_user_mkdirp(int uid, int gid, const char *root, const char *path,
                   int mode) {
    if (!as_user_valid_path(root, path)) {
        return -EPERM;
    }
    /* The storage root itself is assumed to exist (it is the mount/tmpfs);
     * never create or recurse above it. */
    size_t rlen = strlen(root);
    if (strcmp(path, root) == 0 ||
        (strncmp(path, root, rlen) == 0 && path[rlen] == '/' && path[rlen + 1] == '\0')) {
        return 0;
    }
    if (strlen(path) >= PATH_MAX) {
        return -ENAMETOOLONG;
    }
    const char *slash = strrchr(path, '/');
    if (slash == NULL || slash == path) {
        return -EINVAL;
    }
    char parent[PATH_MAX];
    size_t plen = (size_t)(slash - path);
    memcpy(parent, path, plen);
    parent[plen] = '\0';
    if (strcmp(parent, root) != 0) {
        int r = as_user_mkdirp(uid, gid, root, parent, mode);
        if (r != 0) {
            return r;
        }
    }
    int switched = as_user_switch(uid, gid);
    if (switched != 0) {
        return switched;
    }
    int rc = mkdir(path, (mode_t)mode);
    int saved = errno;
    as_user_restore();
    if (rc != 0 && saved != EEXIST) {
        return -saved;
    }
    return 0;
}

/*
 * Data-path helpers: the fd was opened as the mapped user, so no privilege
 * change is needed here (permissions are fixed at open() time). These wrap
 * libc so the caller never has to read the process-global errno from Lua.
 * n is bounded by receive_buffer_size (fits in int).
 */
int as_user_write(int fd, const char *buf, int n) {
    ssize_t r = write(fd, buf, (size_t)n);
    if (r < 0) {
        return -errno;
    }
    return (int)r;
}

int as_user_close_fd(int fd) {
    int r = close(fd);
    if (r != 0) {
        return -errno;
    }
    return 0;
}
