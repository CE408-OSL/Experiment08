#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
};

static ssize_t (*real_getdents64)(int, void*, size_t) = NULL;
static int (*real___xstat)(int, const char*, struct stat*) = NULL;
static int (*real_lstat)(const char*, struct stat*) = NULL;

static int fake_file_returned = 0;
static int fake_dir_returned = 0;

int is_fake_path(const char* path, int* type) {
    size_t path_len = strlen(path);
    size_t file_len = strlen("faketext.txt");
    size_t dir_len = strlen("fakefile");

    if (path_len >= file_len && strcmp(path + path_len - file_len, "faketext.txt") == 0) {
        *type = DT_REG;
        return 1;
    }
    
    if (path_len >= dir_len && strcmp(path + path_len - dir_len, "fakefile") == 0) {
        *type = DT_DIR;
        return 1;
    }

    *type = 0;
    return 0;
}

ssize_t getdents64(int fd, void* dirp, size_t count) {
    if (!real_getdents64) {
        real_getdents64 = dlsym(RTLD_NEXT, "getdents64");
    }

    ssize_t bytes_read = real_getdents64(fd, dirp, count);
    if (bytes_read == -1) {
        return -1;
    }

    struct linux_dirent64* d;
    char* bpos;

    if (!fake_file_returned && !fake_dir_returned) {
        d = (struct linux_dirent64*) dirp;
        bpos = (char*) dirp;

        if (count - bytes_read >= sizeof(struct linux_dirent64) + strlen("fakefile") + 1) {
            d->d_ino = 12345679;
            d->d_off = bytes_read;
            d->d_type = DT_DIR;
            strcpy(d->d_name, "fakefile");
            d->d_reclen = sizeof(struct linux_dirent64) + strlen(d->d_name) + 1;
            
            bytes_read += d->d_reclen;
            d = (struct linux_dirent64*)((char*)d + d->d_reclen);
            fake_dir_returned = 1;
        }

        if (count - bytes_read >= sizeof(struct linux_dirent64) + strlen("faketext.txt") + 1) {
            d->d_ino = 12345678;
            d->d_off = bytes_read;
            d->d_type = DT_REG;
            strcpy(d->d_name, "faketext.txt");
            d->d_reclen = sizeof(struct linux_dirent64) + strlen(d->d_name) + 1;

            bytes_read += d->d_reclen;
            fake_file_returned = 1;
        }
    }

    return bytes_read;
}


int __xstat(int ver, const char *path, struct stat *buf) {
    if (!real___xstat) {
        real___xstat = dlsym(RTLD_NEXT, "__xstat");
    }

    int type;
    if (is_fake_path(path, &type)) {
        memset(buf, 0, sizeof(struct stat));
        buf->st_uid = geteuid();
        buf->st_gid = getegid();
        buf->st_ino = (type == DT_REG) ? 12345678 : 12345679;

        if (type == DT_REG) {
            buf->st_mode = S_IFREG | 0755;
            buf->st_size = 100;
        } else {
            buf->st_mode = S_IFDIR | 0755;
            buf->st_size = 4096;
        }
        return 0;
    }
    return real___xstat(ver, path, buf);
}

int lstat(const char *path, struct stat *buf) {
    if (!real_lstat) {
        real_lstat = dlsym(RTLD_NEXT, "lstat");
    }

    int type;
    if (is_fake_path(path, &type)) {
        memset(buf, 0, sizeof(struct stat));
        buf->st_uid = geteuid();
        buf->st_gid = getegid();
        buf->st_ino = (type == DT_REG) ? 12345678 : 12345679;

        if (type == DT_REG) {
            buf->st_mode = S_IFREG | 0755;
            buf->st_size = 100;
        } else {
            buf->st_mode = S_IFDIR | 0755;
            buf->st_size = 4096;
        }
        return 0;
    }
    return real_lstat(path, buf);
}

void print_fake_names() __attribute__((constructor));
void print_fake_names() {
    printf("%s    %s\n", "fakefile", "faketext.txt");
}
