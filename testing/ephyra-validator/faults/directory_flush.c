// Test-only macOS fault injector. Loaded into an isolated test child with
// DYLD_INSERT_LIBRARIES after the slashing record has been created.
#ifdef __APPLE__
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DYLD_INTERPOSE(replacement, replacee) \
    __attribute__((used)) static struct { const void *a; const void *b; } \
    interpose_##replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&replacement, (const void *)(uintptr_t)&replacee \
    }

static int is_target_directory(int fd) {
    const char *target = getenv("EPHYRA_FAIL_DIRECTORY_FLUSH");
    if (!target || !*target) return 0;
    struct stat descriptor;
    struct stat directory;
    if (fstat(fd, &descriptor) != 0 || !S_ISDIR(descriptor.st_mode)) return 0;
    if (stat(target, &directory) != 0) return 0;
    if (descriptor.st_dev != directory.st_dev || descriptor.st_ino != directory.st_ino) return 0;
    char marker[MAXPATHLEN];
    if (snprintf(marker, sizeof(marker), "%s/.ephyra_fault_active", target) >= (int)sizeof(marker)) {
        return 0;
    }
    return access(marker, F_OK) == 0;
}

static int injected_fsync(int fd) {
    if (is_target_directory(fd)) {
        errno = EIO;
        return -1;
    }
    return (int)syscall(SYS_fsync, fd);
}

static int fcntl_has_no_argument(int command) {
    switch (command) {
        case F_GETFD:
        case F_GETFL:
        case F_GETOWN:
        case F_GETNOSIGPIPE:
            return 1;
        default:
            return 0;
    }
}

static int injected_fcntl(int fd, int command, ...) {
    if (command == F_FULLFSYNC && is_target_directory(fd)) {
        errno = EIO;
        return -1;
    }
    uintptr_t argument = 0;
    if (!fcntl_has_no_argument(command)) {
        va_list arguments;
        va_start(arguments, command);
        argument = va_arg(arguments, uintptr_t);
        va_end(arguments);
    }
    return (int)syscall(SYS_fcntl, fd, command, argument);
}

DYLD_INTERPOSE(injected_fsync, fsync);
DYLD_INTERPOSE(injected_fcntl, fcntl);
#endif
