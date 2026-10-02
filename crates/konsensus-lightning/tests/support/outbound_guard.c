// Test-process-only network guard. Loaded before any Rust/runtime code runs.
// Reject before DNS or connect so even a swallowed fallback error fails the test
// without contacting that host. The sole allowed peer is the parent's Core or Electrum fixture.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void record(const char *operation, const char *host, int port, int allowed) {
    const char *path = getenv("BITSOV_GUARD_LOG");
    int fd = path ? open(path, O_WRONLY | O_APPEND | O_CREAT, 0600) : -1;
    if (fd < 0) _exit(87);
    dprintf(fd, "%s %s %s:%d\n", allowed ? "ALLOW" : "DENY", operation, host, port);
    close(fd);
    if (!allowed) _exit(86);
}

static int guarded_getaddrinfo(const char *host, const char *service,
                              const struct addrinfo *hints, struct addrinfo **result) {
    record("resolve", host ? host : "<null>", 0, host && !strcmp(host, "127.0.0.1"));
#ifdef __APPLE__
    // dyld excludes calls from the interposing image. dlsym would rebind to us.
    return getaddrinfo(host, service, hints, result);
#else
    int (*real_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **) =
        dlsym(RTLD_NEXT, "getaddrinfo");
    if (!real_fn) _exit(87);
    return real_fn(host, service, hints, result);
#endif
}

static int guarded_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (addr && addr->sa_family != AF_UNIX) {
        char host[INET6_ADDRSTRLEN] = "<unknown>";
        int port = 0;
        if (addr->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &ipv4->sin_addr, host, sizeof(host));
            port = ntohs(ipv4->sin_port);
        } else if (addr->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &ipv6->sin6_addr, host, sizeof(host));
            port = ntohs(ipv6->sin6_port);
        }
        const char *fixture_port = getenv("BITSOV_GUARD_PORT");
        record("connect", host, port, fixture_port && !strcmp(host, "127.0.0.1") &&
               port == atoi(fixture_port) && port != 3141);
    }
#ifdef __APPLE__
    return connect(fd, addr, len);
#else
    int (*real_fn)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "connect");
    if (!real_fn) _exit(87);
    return real_fn(fd, addr, len);
#endif
}

#ifdef __APPLE__
__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } interposers[] = {
    { (const void *)guarded_connect, (const void *)connect },
    { (const void *)guarded_getaddrinfo, (const void *)getaddrinfo },
};
#else
int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    return guarded_connect(fd, addr, len);
}
int getaddrinfo(const char *host, const char *service,
                const struct addrinfo *hints, struct addrinfo **result) {
    return guarded_getaddrinfo(host, service, hints, result);
}
#endif
