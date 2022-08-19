#ifndef __ELF_READER_H__
#define __ELF_READER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <elf.h>

#define MAX_LEN_FILENAME (128)
#define MAX_INPUT_SZ (64)
#define NUM_INPUT_FIELDS (3)
#define MAX_SPEC_SZ (8)
#define MAX_INP_READ_SZ (3)
#define PAGE_SIZE (1 << 12)

enum file_status {
    enum_open = 0,
    enum_close
};

struct prog_region {
    Elf64_Addr vaddr;
    uint64_t memsz;
    uint64_t filesz;
    uint32_t idx; // idx in prog_hdr
    uint32_t flags;
    uint32_t num_pages;
    void *addr;
};
struct elf64_file {
    char fname[MAX_LEN_FILENAME];
    FILE *fp;
    enum file_status file_status;
    unsigned long file_size;
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr;
    int num_regions;
    struct prog_region **prog_regions;
    void (*print_elf_hdr)(struct elf64_file *elf);
};

void init_limits(const char limit_file[MAX_LEN_FILENAME]);
void init_elf64_file(const char filename[MAX_LEN_FILENAME],
		     struct elf64_file *elf);
void fini_elf64_file(struct elf64_file *elf);


#endif
