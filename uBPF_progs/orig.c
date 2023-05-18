#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include "../vm/inc/ubpf.h"

static int read_binary_file(const char *filename, uint8_t **buf, size_t *len) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    off_t file_len = lseek(fd, 0, SEEK_END);
    if (file_len == (off_t) -1) {
        perror("lseek");
        close(fd);
        return -1;
    }

    *buf = malloc(file_len);
    if (!*buf) {
        perror("malloc");
        close(fd);
        return -1;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t) -1) {
        perror("lseek");
        free(*buf);
        close(fd);
        return -1;
    }

    ssize_t n = read(fd, *buf, file_len);
    if (n < 0 || n != file_len) {
        perror("read");
        free(*buf);
        close(fd);
        return -1;
    }

    close(fd);
    *len = n;

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path to eBPF bytecode file>\n", argv[0]);
        return 1;
    }

    uint8_t *buf;
    size_t buf_len;

    if (read_binary_file(argv[1], &buf, &buf_len
) != 0) {
        fprintf(stderr, "Failed to read bytecode file\n");
        return 1;
    }

    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create uBPF VM\n");
        free(buf);
        return 1;
    }

    char *errmsg;
    int rv = ubpf_load_elf(vm, buf, buf_len, &errmsg);
    if (rv < 0) {
        fprintf(stderr, "Failed to load eBPF bytecode: %s\n", errmsg);
        ubpf_destroy(vm);
        free(buf);
        return 1;
    }

    // Register helper functions if required.
    // For example:
    // ubpf_register(vm, BPF_FUNC_map_lookup_elem, my_map_lookup_elem);

    // Execute the eBPF program
    uint64_t ret;
    
    rv = ubpf_exec(vm, NULL, 0, &ret);

    printf("eBPF program executed, return value: %" PRIu64 "\n", ret);

    ubpf_destroy(vm);
    free(buf);

    return 0;
}
