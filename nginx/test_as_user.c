/*
 * test_as_user.c — unit tests for as_user.c.
 *
 * Two modes:
 *
 * "root" — must run as root. Verifies that every operation actually
 * switches to the mapped user's effective credentials (the DAC outcome is
 * the proof: the root worker would bypass the permission checks asserted
 * here), plus the storage-root path containment and the negated-errno
 * return convention.
 *
 * "nonroot" — runs as root, drops to a plain non-root uid (a plain
 * setuid() clears the capability sets, modeling a non-root nginx worker
 * without CAP_SETUID/CAP_SETGID in its effective set), and verifies the
 * fail-closed guard: every operation returns -EPERM and the process
 * identity survives the failed switches.
 *
 * The build stage (nginx.dockerfile) runs both modes so a regression
 * fails the image build; the binary is also shipped in the runtime image
 * (/usr/local/bin/test_as_user) so the pytest suite re-runs it
 * (tests/test_user_ownership.py::test_c_module_unit_tests).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h> /* setgroups(2) */
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

/* Same ABI as the shared object; the test binary links as_user.c
 * directly. */
int as_user_mkdirp(int uid, int gid, const char *root, const char *path, int mode);
int as_user_open(int uid, int gid, const char *root, const char *path, int flags, int mode);
int as_user_unlink(int uid, int gid, const char *root, const char *path);
int as_user_rename(int uid, int gid, const char *root, const char *src, const char *dst);
int as_user_write(int fd, const char *buf, int n);
int as_user_close_fd(int fd);
int as_user_setxattr(int uid, int gid, const char *root, const char *path,
                     const char *name, const char *value, size_t size, int flags);

#define TUID 10001
#define TGID 20001
/* A group that is neither the mapped user's primary group nor a group the
 * mapped user belongs to: the worker's supplementary group in the
 * supplementary-group test (see root_mode). */
#define SGID 20002

static int failures = 0;
static int checks = 0;

static void check(int cond, const char *msg) {
    checks++;
    if (cond) {
        printf("PASS %s\n", msg);
    } else {
        printf("FAIL %s\n", msg);
        failures++;
    }
}

static int file_uid(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    return (int)st.st_uid;
}

static int file_gid(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    return (int)st.st_gid;
}

static long file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    return (long)st.st_size;
}

/* One-shot alarm handler: interrupts the writer's blocked write() to
 * exercise the EINTR retry path of as_user_write. Classic signal(3)
 * semantics reset the disposition to SIG_DFL after delivery, so it fires
 * exactly once. */
static void alarm_handler(int sig) {
    (void)sig;
}

/* Reader thread for the as_user_write full-write test: drains the pipe,
 * counting exactly how many bytes arrive. It blocks SIGALRM so the alarm
 * can only interrupt the writer thread, and sleeps delay_ms before the
 * first read so the writer's first write() deterministically fills the
 * pipe and blocks (a blocking write to a pipe with a live reader would
 * otherwise return the full count and the short-write/EINTR paths would
 * never be exercised). */
struct pipe_drain {
    int fd;
    long total;
    long delay_ms;
};

static void *drain_pipe(void *arg) {
    struct pipe_drain *pd = arg;
    sigset_t block;
    char buf[4096];
    sigemptyset(&block);
    sigaddset(&block, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &block, NULL);
    if (pd->delay_ms > 0) {
        usleep((useconds_t)(pd->delay_ms * 1000));
    }
    for (;;) {
        ssize_t r = read(pd->fd, buf, sizeof buf);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (r == 0) {
            break;
        }
        pd->total += r;
    }
    return NULL;
}

static int root_mode(const char *base, const char *root) {
    char path[4096];
    char src[4096];
    char dst[4096];
    int fd;

    /* World-writable sandbox: the mapped user (and root) can both create
     * entries directly under it. */
    if (chmod(base, 0777) != 0) {
        perror("chmod base");
        return 2;
    }
    /* Give the (root) worker a supplementary group (SGID) that will own a
     * group-writable directory: models the image's own `chgrp 0 +
     * chmod g=u` layout, where the worker's group is the directory's
     * group. This must happen before the first as_user call: the worker's
     * groups are captured on the first switch. */
    {
        static const gid_t worker_suppl[] = { SGID };
        if (setgroups(1, worker_suppl) != 0) {
            perror("setgroups");
            return 2;
        }
    }
    /* The mapped user's private directory, and a root-owned one. */
    snprintf(path, sizeof path, "%s/a", base);
    if (mkdir(path, 0700) != 0 || chown(path, TUID, TGID) != 0) {
        perror("setup a");
        return 2;
    }
    snprintf(path, sizeof path, "%s/b", base);
    if (mkdir(path, 0755) != 0) {
        perror("setup b");
        return 2;
    }

    /* 1. open+write as the mapped user: the file lands owned by the
     * mapped uid:gid (root would have bypassed the DAC checks in dir a). */
    snprintf(path, sizeof path, "%s/a/f.txt", base);
    fd = as_user_open(TUID, TGID, root, path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    check(fd >= 0, "open for write as mapped user succeeds");
    if (fd >= 0) {
        check(as_user_write(fd, "hello", 5) == 5, "write over the user-opened fd");
        check(as_user_close_fd(fd) == 0, "close of the user-opened fd");
    }
    check(file_uid(path) == TUID && file_gid(path) == TGID,
          "file owned by the mapped uid:gid");
    check(file_size(path) == 5, "file size after write");

    /* 2. Directory creation as the mapped user: every created directory
     * is owned by the mapped uid:gid. */
    snprintf(path, sizeof path, "%s/c/d", base);
    check(as_user_mkdirp(TUID, TGID, root, path, 0755) == 0,
          "mkdirp as mapped user succeeds");
    snprintf(path, sizeof path, "%s/c", base);
    check(file_uid(path) == TUID && file_gid(path) == TGID,
          "parent directory owned by the mapped uid:gid");
    snprintf(path, sizeof path, "%s/c/d", base);
    check(file_uid(path) == TUID && file_gid(path) == TGID,
          "leaf directory owned by the mapped uid:gid");
    check(as_user_mkdirp(TUID, TGID, root, root, 0755) == 0,
          "mkdirp of the storage root itself is a no-op");

    /* 3. Path containment: ".." segments and paths outside the root are
     * rejected with -EPERM; ".." inside a longer name is not. */
    snprintf(path, sizeof path, "%s/../escape", base);
    check(as_user_open(TUID, TGID, root, path, O_WRONLY | O_CREAT, 0644) == -EPERM,
          "path escaping the root via .. is rejected");
    snprintf(path, sizeof path, "%s/a/../b/ok", base);
    check(as_user_open(TUID, TGID, root, path, O_WRONLY | O_CREAT, 0644) == -EPERM,
          "embedded .. segment is rejected");
    check(as_user_open(TUID, TGID, root, "/etc/passwd", O_WRONLY | O_CREAT, 0644) == -EPERM,
          "path outside the root is rejected");
    check(as_user_mkdirp(TUID, TGID, root, "/tmp/asu-x", 0755) == -EPERM,
          "mkdirp outside the root is rejected");
    check(as_user_unlink(TUID, TGID, root, "/etc/passwd") == -EPERM,
          "unlink outside the root is rejected");
    snprintf(path, sizeof path, "%s/..dot.txt", base);
    fd = as_user_open(TUID, TGID, root, path, O_WRONLY | O_CREAT, 0644);
    check(fd >= 0, "'..' inside a longer name (..dot.txt) is a valid name");
    if (fd >= 0) {
        as_user_close_fd(fd);
    }

    /* 4. rename runs as the mapped user: DAC on the directories applies. */
    snprintf(path, sizeof path, "%s/b/rootf", base);
    fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        perror("setup rootf");
        return 2;
    }
    close(fd);
    snprintf(src, sizeof src, "%s/b/rootf", base);
    snprintf(dst, sizeof dst, "%s/b/rootf2", base);
    check(as_user_rename(TUID, TGID, root, src, dst) == -EACCES,
          "rename in a root-owned directory is denied for the mapped user");
    check(as_user_rename(0, 0, root, src, dst) == 0,
          "rename as the root worker succeeds");
    check(as_user_unlink(TUID, TGID, root, dst) == -EACCES,
          "unlink in a root-owned directory is denied for the mapped user");
    check(as_user_unlink(0, 0, root, dst) == 0,
          "unlink as the root worker succeeds");

    /* 5. setxattr runs as the mapped user: the user.* xattr write requires
     * write access to the file, which the root worker would bypass. */
    snprintf(path, sizeof path, "%s/a/g.txt", base);
    fd = as_user_open(TUID, TGID, root, path, O_WRONLY | O_CREAT, 0644);
    check(fd >= 0, "open for the setxattr tests");
    if (fd >= 0) {
        as_user_close_fd(fd);
    }
    check(as_user_setxattr(TUID, TGID, root, path, "user.test", "v1", 2, 0) == 0,
          "setxattr on the mapped user's own file succeeds");
    {
        char buf[64];
        long n = getxattr(path, "user.test", buf, sizeof buf);
        check(n == 2 && memcmp(buf, "v1", 2) == 0, "setxattr value is readable");
    }
    snprintf(path, sizeof path, "%s/b/rootx", base);
    fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        perror("setup rootx");
        return 2;
    }
    close(fd);
    check(as_user_setxattr(TUID, TGID, root, path, "user.test", "v1", 2, 0) == -EACCES,
          "setxattr on a foreign file is denied for the mapped user (proves the effective-uid switch)");

    /* 6. errno conventions on the data-path wrappers. */
    check(as_user_write(-1, "x", 1) == -EBADF, "write to a bad fd returns -EBADF");
    check(as_user_close_fd(-1) == -EBADF, "close of a bad fd returns -EBADF");

    /* 7. Supplementary groups: the worker's supplementary group (SGID,
     * captured at the first switch) must not be visible to the mapped
     * user: a group-writable directory owned by SGID is unreachable for a
     * mapped user that is not in it. (Before the fix the switch left the
     * worker's groups in place and this open succeeded.) */
    snprintf(path, sizeof path, "%s/gshared", base);
    if (mkdir(path, 0777) != 0 || chown(path, 0, SGID) != 0 || chmod(path, 0770) != 0) {
        perror("setup gshared");
        return 2;
    }
    snprintf(path, sizeof path, "%s/gshared/f.txt", base);
    check(as_user_open(TUID, TUID, root, path, O_WRONLY | O_CREAT, 0644) == -EACCES,
          "open into a group-writable dir is denied: the worker's supplementary groups are dropped");
    check(file_size(path) == -1,
          "no file is created via the worker's supplementary group");

    /* 8. as_user_write delivers the whole buffer even when write() is
     * interrupted: the reader thread is held off (100 ms) behind the
     * alarm (20 ms), so the writer's first write() fills the pipe (a
     * 64 KB pipe, 256 KB buffer) and blocks, and SIGALRM interrupts it
     * with EINTR while 64 KB is in flight. A correct implementation
     * retries and returns the full buffer size; one that returns the
     * error (or a short count) loses data that the caller's checksum
     * still covers. */
    {
        int pfd[2];
        struct pipe_drain pd;
        struct itimerval it;
        pthread_t th;
        static char big[256 * 1024];
        memset(big, 'A', sizeof big);
        if (pipe(pfd) != 0) {
            perror("pipe");
            return 2;
        }
        pd.fd = pfd[0];
        pd.total = 0;
        pd.delay_ms = 100;
        if (pthread_create(&th, NULL, drain_pipe, &pd) != 0) {
            perror("pthread_create");
            return 2;
        }
        signal(SIGALRM, alarm_handler);
        memset(&it, 0, sizeof it);
        it.it_value.tv_usec = 20000; /* one-shot, 20 ms */
        setitimer(ITIMER_REAL, &it, NULL);
        int w = as_user_write(pfd[1], big, (int)sizeof big);
        close(pfd[1]);
        pthread_join(th, NULL);
        close(pfd[0]);
        check(w == (int)sizeof big,
              "an interrupted write is retried: as_user_write returns the full size");
        check(pd.total == (long)sizeof big,
              "the reader received exactly the bytes the write reported");
    }

    return failures;
}

static int nonroot_mode(void) {
    /* Drop privileges for good: a plain setuid() clears the capability
     * sets, so this models a non-root worker whose effective set lacks
     * CAP_SETUID/CAP_SETGID (file capabilities on the binary are the only
     * way such a worker can switch). */
    if (setgid(TGID) != 0 || setuid(TUID) != 0) {
        perror("setgid/setuid");
        return 2;
    }
    check(getuid() == TUID && geteuid() == TUID, "dropped to a non-root uid");

    char tmplate[] = "/tmp/asu-nr-XXXXXX";
    char *base = mkdtemp(tmplate);
    if (!base) {
        perror("mkdtemp");
        return 2;
    }
    char root[4096];
    char path[4096];
    char src2[4096];
    char dst2[4096];
    snprintf(root, sizeof root, "%s", base);
    snprintf(path, sizeof path, "%s/f.txt", base);
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        perror("open");
        return 2;
    }
    close(fd);
    snprintf(src2, sizeof src2, "%s/f.txt", base);
    snprintf(dst2, sizeof dst2, "%s/g.txt", base);

    check(as_user_open(TUID, TGID, root, path, O_WRONLY, 0) == -EPERM,
          "open fails closed without CAP_SETUID");
    check(as_user_mkdirp(TUID, TGID, root, dst2, 0755) == -EPERM,
          "mkdirp fails closed without CAP_SETUID");
    check(as_user_unlink(TUID, TGID, root, path) == -EPERM,
          "unlink fails closed without CAP_SETUID");
    check(as_user_rename(TUID, TGID, root, src2, dst2) == -EPERM,
          "rename fails closed without CAP_SETUID");
    check(as_user_setxattr(TUID, TGID, root, path, "user.test", "v", 1, 0) == -EPERM,
          "setxattr fails closed without CAP_SETUID");

    /* The failed switches must not have disturbed the process identity. */
    check(getuid() == TUID && geteuid() == TUID && getgid() == TGID && getegid() == TGID,
          "worker identity intact after failed switches");

    return failures;
}

int main(int argc, char **argv) {
    /* The failure paths below exit without flushing; keep stdout
     * unbuffered so the results are never lost. */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: %s root|nonroot\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "root") == 0) {
        if (geteuid() != 0) {
            fprintf(stderr, "root mode must run as root\n");
            return 2;
        }
        char tmplate[] = "/tmp/asu-root-XXXXXX";
        char *base = mkdtemp(tmplate);
        if (!base) {
            perror("mkdtemp");
            return 2;
        }
        char root[4096];
        snprintf(root, sizeof root, "%s", base);
        int r = root_mode(base, root);
        /* Best-effort cleanup of the sandbox. */
        char cmd[4128];
        snprintf(cmd, sizeof cmd, "rm -rf %s", base);
        int cleanup = system(cmd);
        (void)cleanup;
        printf("%s: %d checks, %d failures\n", argv[0], checks, r);
        return r != 0;
    }
    if (strcmp(argv[1], "nonroot") == 0) {
        int r = nonroot_mode();
        printf("%s: %d checks, %d failures\n", argv[0], checks, r);
        return r != 0;
    }
    fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 2;
}
