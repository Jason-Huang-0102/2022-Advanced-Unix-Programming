#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#define fd_global 500

#define LOG(fn, ret, fmt, ...) \
    do { \
        dprintf(fd_global, "[logger] %s(" fmt ") = %d\n", #fn, __VA_ARGS__, ret); \
    } while (0)
#define LOG_ADDR(fn, ret, fmt, ...) \
    do { \
        dprintf(fd_global, "[logger] %s(" fmt ") = %p\n", #fn, __VA_ARGS__, ret); \
    } while (0)
#define LOG_L(fn, ret, fmt, ...) \
    do { \
        dprintf(fd_global, "[logger] %s(" fmt ") = %ld\n", #fn, __VA_ARGS__, ret); \
    } while (0)


#define PRELOAD(type, fn, ...) \
    type fn(__VA_ARGS__) { \
       static type (*real_##fn)(__VA_ARGS__) = NULL; \
       if (real_##fn == NULL) { \
           *(void**)(&real_##fn) = dlsym(RTLD_NEXT, #fn); \
       }

char *getpath(const char *path) {
    static char realp[512];
    realpath(path, realp);
    return realp;
}

char *getname(FILE *f) {
    static char filename[512];
    char proclink[128];
    int fd = fileno(f);

    memset(filename, 0, sizeof(filename));
    snprintf(proclink, 128, "/proc/self/fd/%d", fd);
    readlink(proclink, filename, 512);
    return filename;
}

char *first_32(const char *s, size_t sz) {
    static char ret_s[33];
    size_t idx = 0;
    memset(ret_s, 0, sizeof(ret_s));

    for (;idx < sz && idx < 32 && s[idx]; ++idx) {
        if (isprint(s[idx])) ret_s[idx] = s[idx];
        else ret_s[idx] = '.';
    }
    return ret_s;
}

PRELOAD(int, chmod, const char *pathname, mode_t mode) {
    int ret = real_chmod(pathname, mode);
    LOG(chmod, ret, "\"%s\", %o", getpath(pathname), mode);
    return ret;
}}

PRELOAD(int, chown, const char *pathname, uid_t owner, gid_t group) {
    int ret = real_chown(pathname, owner, group);
    LOG(chmod, ret, "\"%s\", %d, %d\"", getpath(pathname), owner, group);
    return ret;
}}

PRELOAD(int, close, int fd) {
    int ret = real_close(fd);
    LOG(close, ret, "%d", fd);
    return ret;
}}

PRELOAD(int, creat, const char *pathname, mode_t mode) {
    int ret = real_creat(pathname, mode);
    LOG(creat, ret, "\"%s\", %o", getpath(pathname), mode);
    return ret;
}}

PRELOAD(int, creat64, const char *pathname, mode_t mode) {
    int ret = real_creat64(pathname, mode);
    LOG(creat64, ret, "\"%s\", %o", getpath(pathname), mode);
    return ret;
}}

PRELOAD(int, fclose, FILE *stream) {
    char *name = getname(stream);
    int ret = real_fclose(stream);
    LOG(fclose, ret, "\"%s\"", name);
    return ret;
}}

PRELOAD(FILE*, fopen, const char *pathname, const char *mode) {
    FILE *file = real_fopen(pathname, mode);
    LOG_ADDR(fopen, file, "\"%s\", \"%s\"", getpath(pathname), first_32(mode, strlen(pathname)));
    return file;
}}

PRELOAD(FILE*, fopen64, const char *pathname, const char *mode) {
    FILE *file = real_fopen64(pathname, mode);
    LOG_ADDR(fopen64, file, "\"%s\", \"%s\"", getpath(pathname), first_32(mode, strlen(pathname)));
    return file;
}}

PRELOAD(size_t, fread, void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t sz = real_fread(ptr, size, nmemb, stream);
    LOG_L(fread, sz, "%p, %ld, %ld, \"%s\"", first_32(ptr, 32), size, nmemb, getname(stream));
    return sz;
}}

PRELOAD(size_t, fread64, void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t sz = real_fread64(ptr, size, nmemb, stream);
    LOG_L(fread64, sz, "%p, %ld, %ld, \"%s\"", first_32(ptr, 32), size, nmemb, getname(stream));
    return sz;
}}

PRELOAD(size_t, fwrite, const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t sz = real_fwrite(ptr, size, nmemb, stream);
    LOG_L(fwrite, sz, "\"%s\", %ld, %ld, \"%s\"", first_32(ptr, sz), size, nmemb, getname(stream));
    return sz;
}}

PRELOAD(size_t, fwrite64, const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t sz = real_fwrite64(ptr, size, nmemb, stream);
    LOG_L(fwrite64, sz, "\"%s\", %ld, %ld, \"%s\"", first_32(ptr, sz), size, nmemb, getname(stream));
    return sz;
}}

PRELOAD(int, open, const char *pathname, int flags, mode_t mode) {
    int ret = real_open(pathname, flags, mode);
    LOG(open, ret, "\"%s\", %o, %o", getpath(pathname), flags, mode);
    return ret;
}}

PRELOAD(int, open64, const char *pathname, int flags, mode_t mode) {
    int ret = real_open64(pathname, flags, mode);
    LOG(open64, ret, "\"%s\", %o, %o", getpath(pathname), flags, mode);
    return ret;
}}

PRELOAD(ssize_t, read, int fd, void *buf, size_t count) {
    ssize_t sz = real_read(fd, buf, count);
    LOG_L(read, sz, "%d, \"%s\", %ld", fd, first_32(buf, sz), count);
    return sz;
}}

PRELOAD(ssize_t, read64, int fd, void *buf, size_t count) {
    ssize_t sz = real_read64(fd, buf, count);
    LOG_L(read64, sz, "%d, \"%s\", %ld", fd, first_32(buf, sz), count);
    return sz;
}}

PRELOAD(int, remove, const char *pathname) {
    int ret = real_remove(pathname);
    LOG(remove, ret, "\"%s\"", getpath(pathname));
    return ret;
}}

PRELOAD(int, rename, const char *oldpath, const char *newpath) {
    int ret = real_rename(oldpath, newpath);
    LOG(rename, ret, "\"%s\", \"%s\"", getpath(oldpath), getpath(newpath));
    return ret;
}}

PRELOAD(FILE*, tmpfile, void) {
    FILE *file = real_tmpfile();
    LOG_ADDR(tmpfile, file, "", file); // TODO: supress warning
    return file;
}}

PRELOAD(FILE*, tmpfile64, void) {
    FILE *file = real_tmpfile64();
    LOG_ADDR(tmpfile64, file, "", file); // TODO: supress warning
    return file;
}}

PRELOAD(ssize_t, write, int fd, const void *buf, size_t count) {
    ssize_t sz = real_write(fd, buf, count);
    LOG_L(write, sz, "%d, \"%s\", %ld", fd, first_32(buf, sz), count);
    return sz;
}}

PRELOAD(ssize_t, write64, int fd, const void *buf, size_t count) {
    ssize_t sz = real_write64(fd, buf, count);
    LOG_L(write64, sz, "%d, \"%s\", %ld", fd, first_32(buf, sz), count);
    return sz;
}}

