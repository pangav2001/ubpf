#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include "../vm/inc/ubpf.h"
#define	ELFMAG		"\177ELF"
#define	SELFMAG		4
static void*
readfile(const char* path, size_t maxlen, size_t* len)
{
    FILE* file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    char* data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data + offset, 1, maxlen - offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n", path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return (void*)data;
}

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

//     uint8_t *buf;
//     size_t buf_len;

//     if (read_binary_file(argv[1], &buf, &buf_len
// ) != 0) {
//         fprintf(stderr, "Failed to read bytecode file\n");
//         return 1;
//     }

    size_t code_len;
    void* code = readfile(argv[1], 1024 * 1024, &code_len);

    // printf("Hi\n");

    fprintf(stderr, "%d\n", code_len);
    printf("%.*s\n", code_len, code);

    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create uBPF VM\n");
        free(code);
        return 1;
    }

    bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);

    printf("%d", elf);


    char *errmsg;
    int rv = ubpf_load_elf(vm, code, code_len, &errmsg);
    if (rv < 0) {
        fprintf(stderr, "Failed to load eBPF bytecode: %s\n", errmsg);
        ubpf_destroy(vm);
        free(code);
        return 1;
    }

    // Register helper functions if required.
    // For example:
    // ubpf_register(vm, BPF_FUNC_map_lookup_elem, my_map_lookup_elem);

    uint64_t* ret;
    // Execute the eBPF program
    // rv = ubpf_exec(vm, NULL, 0, ret);

    printf("eBPF program executed, return value: %" PRIu64 "\n", ret);

    // ubpf_destroy(vm);
    // free(code);

    return 0;
}
