#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <elf.h>

#include "elf-reader.h"

#define fatal(s, ...) do {printf("%04d: ", __LINE__); printf(s, ##__VA_ARGS__); exit(1);} while(0)
#define GEN_LMT(t, v, l, h) ((*(t *)v >= *(t *)l) && (*(t *)v <= *(t *)h))
#define ADD2DSTR(s, i) (&s[i][0])

enum limits_t {
    ephdr = 0,
    eshdr,
    limits_t_sz
};

enum data_t {
    euint16_t = 0,
    data_t_sz
};

struct limits {
    char spec[NUM_INPUT_FIELDS - 1][MAX_SPEC_SZ];
    enum data_t type;
};

static const char str_limit_t[limits_t_sz][128] =
{
    "ephdr",
    "eshdr",
};
static const char inp_read_str[limits_t_sz][MAX_INP_READ_SZ] =
{
    [ephdr] = "%d",
    [eshdr] = "%d",
};
static const int prot_map[] = {
    [0] = PROT_NONE,
    [1] = PROT_EXEC,
    [2] = PROT_WRITE,
    [3] = PROT_WRITE | PROT_EXEC,
    [4] = PROT_READ,
    [5] = PROT_READ | PROT_EXEC,
    [6] = PROT_READ | PROT_WRITE,
    [7] = PROT_READ | PROT_WRITE | PROT_EXEC
};

static int within_lmts(void *v, enum data_t type, struct limits *l);
static void phex(void *ptr, int b);

static struct limits limits[limits_t_sz];

static void phex(void *ptr, int b)
{
    int i, j;
    unsigned char *c = ptr;
    for(i = 0; i < b; i++) {
	printf("%02X ", c[i]);
	if((i+1)%16 == 0)
	    printf("\n");	
    }
    if(i%16 != 0)
	printf("\n");
}

static int within_lmts(void *v, enum data_t type, struct limits *l)
{
    int in_lmt = 0;

    if((l->type < 0) || (l->type >= data_t_sz))
	fatal("wrong data type\n");

    switch(type) {
    case euint16_t:
	if(GEN_LMT(uint16_t, v, ADD2DSTR(l->spec, 0), ADD2DSTR(l->spec, 1)))
	    in_lmt = 1;
	break;
    default:
	// Not possible
	break;
    }
    return in_lmt;
}

void read_limits(enum limits_t limit, char inp[NUM_INPUT_FIELDS][MAX_INPUT_SZ], struct limits *l)
{
    int i;
    for(i = 1; i < NUM_INPUT_FIELDS; i++)
	sscanf(ADD2DSTR(inp, i), inp_read_str[limit], &(l->spec[i-1]));
}

enum limits_t match_to_limit_type(char *inp)
{
    int i;
    enum limits_t idx = limits_t_sz;
    for(i = 0; i < limits_t_sz; i++) {
	if(strncmp(inp, ADD2DSTR(str_limit_t, i), MAX_INPUT_SZ) == 0) {
	    idx = i;
	    return idx;
	}
    }

    return idx;	
}

void init_limits(const char limit_file[MAX_LEN_FILENAME])
{
    FILE *fp;
    int i, j, match;
    
    char input[NUM_INPUT_FIELDS][MAX_INPUT_SZ];
    if((fp = fopen(limit_file, "r")) == NULL)
	fatal("%s does not exist\n", limit_file);

    for(i = 0; i < limits_t_sz; i++) {
	for(j = 0; j < NUM_INPUT_FIELDS; j++)
	    if(fscanf(fp, "%s", ADD2DSTR(input, j)) <= 0)
		goto fail;
	
	match = match_to_limit_type(ADD2DSTR(input, 0));
	if(match < limits_t_sz)
	    read_limits(match, input, &limits[match]);
	else
	    fatal("bad input %s in %s, match=%d\n",
		  ADD2DSTR(input, 0), limit_file, match);
    }
    goto succ;
    
fail:
    fatal("bad input in %s\n", limit_file);
succ:

    fclose(fp);
    return;
}

void print_elf_hdr_64(struct elf64_file *elf)
{
    int i;

    for(i = 0; i < EI_NIDENT; i++) {
	printf("%02X ", elf->ehdr.e_ident[i]);
    }
    printf("\n");

    for(i = 0; i < elf->ehdr.e_phnum; i++) {
	printf("ph %02d: ", i);
	printf("%08X %02X %-10ld 0x%016lX 0x%016lX %06lX %06lX %06lX\n",
               elf->phdr[i].p_type,
               elf->phdr[i].p_flags,
               elf->phdr[i].p_offset,
               elf->phdr[i].p_vaddr,
               elf->phdr[i].p_paddr,
               elf->phdr[i].p_filesz,
               elf->phdr[i].p_memsz,
               elf->phdr[i].p_align
	    );
    }

    printf("Loadable segments are = \n");
    printf("%-3s %-16s %-6s %-6s %-6s %-6s\n", "Num", "vaddr", "memsz", "filesz",
	   "npages", "flags");
    for(i = 0; i < elf->num_regions; i++) {
	printf("%03d %016lX %06lX %06lX %06X %06X\n",
	       i,
	       elf->prog_regions[i]->vaddr,
	       elf->prog_regions[i]->memsz,
	       elf->prog_regions[i]->filesz,
	       elf->prog_regions[i]->num_pages,
	       elf->prog_regions[i]->flags);
    }
}

void init_elf64_file(const char filename[MAX_LEN_FILENAME],
		     struct elf64_file *elf) {

    int i, j;
    uint16_t phentsize, phnum;
    Elf64_Off phoff;
    
    strncpy(elf->fname, filename, sizeof(elf->fname));

    elf->fp = fopen(elf->fname, "r");
    if(elf->fp == NULL)
	fatal("unable to open %s", elf->fname);

    elf->file_status = enum_open;

    fseek(elf->fp, 0, SEEK_END);
    elf->file_size = ftell(elf->fp);
    if(elf->file_status == enum_close)
	fatal("Trying to read closed file %s\n", elf->fname);

    fseek(elf->fp, 0, SEEK_SET);
    if(fread(&elf->ehdr, sizeof(elf->ehdr), 1, elf->fp) != 1)
	fatal("Cannot read elf hdr\n");

    if(elf->ehdr.e_phoff >= elf->file_size)
	fatal("wrong phoff, phoff= %lu, file size = %lu\n",
	      elf->ehdr.e_phoff, elf->file_size);
    elf->print_elf_hdr = print_elf_hdr_64;

    phoff = elf->ehdr.e_phoff;
    phentsize = elf->ehdr.e_phentsize;
    phnum = elf->ehdr.e_phnum;

    if(!within_lmts(&phentsize, ephdr, &limits[ephdr]))
	fatal("phdrsz not within limits. phdrsz = 0x%04X\n", phentsize);

    elf->phdr = (Elf64_Phdr *)calloc(phnum, sizeof(Elf64_Phdr));
    if(elf->phdr == NULL)
	fatal("could not allocate %d of %ld bytes\n",
	      phnum, sizeof(Elf64_Phdr));
    if(fread(elf->phdr, sizeof(Elf64_Phdr), phnum, elf->fp) != phnum)
	fatal("cannot read phdr\n");

    elf->num_regions = 0;
    for(i = 0; i < phnum; i++) {
	if(elf->phdr[i].p_type == PT_LOAD) {
	    elf->num_regions++;
	}
    }
    elf->prog_regions =
	(struct prog_region **)calloc(elf->num_regions,
				      sizeof(struct prog_region *));
    if(elf->prog_regions == NULL)
	fatal("unexpected");
    j = 0;
    for(i = 0; i < phnum; i++) {
	if(elf->phdr[i].p_type == PT_LOAD) {
	    elf->prog_regions[j] =
		(struct prog_region *)malloc(sizeof(struct prog_region));
	    if(elf->prog_regions[j] == NULL)
		fatal("not expected\n");
	    elf->prog_regions[j]->idx = i;
	    j++;
	}
    }

    for(i = 0; i < elf->num_regions; i++) {
	Elf64_Addr first_page, last_page, dest;
	uint32_t add, num_pages, flags;
	size_t rbytes;
	j = elf->prog_regions[i]->idx;
	elf->prog_regions[i]->memsz	= elf->phdr[j].p_memsz;
	elf->prog_regions[i]->filesz	= elf->phdr[j].p_filesz;
	elf->prog_regions[i]->vaddr	= elf->phdr[j].p_vaddr;
        flags				= elf->phdr[j].p_flags;
	elf->prog_regions[i]->flags = flags;
	first_page = elf->phdr[j].p_vaddr & (~0xFFF);
	last_page  = (elf->phdr[j].p_vaddr + elf->phdr[j].p_memsz);
	if((last_page & 0xFFF) == 0)
	    add = 0;
	else
	    add = 1;
	last_page = last_page & (~0xFFF);
	
	num_pages = (last_page - first_page) / PAGE_SIZE + add;
	elf->prog_regions[i]->num_pages = num_pages;
	if(elf->prog_regions[i]->vaddr == 0 || num_pages == 0)
	    continue;
	elf->prog_regions[i]->addr
	    = (void *)mmap(NULL, num_pages * PAGE_SIZE,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   -1, 0);
	if(elf->prog_regions[i]->addr == MAP_FAILED)
	    fatal("mmap returned error %s\n", strerror(errno));

	dest = (Elf64_Addr)elf->prog_regions[i]->addr +
	    (elf->prog_regions[i]->vaddr & 0xFFF);
	if(fseek(elf->fp, elf->phdr[j].p_offset , SEEK_SET) == -1)
	    fatal("cant fseek to %ld\n", elf->phdr[j].p_offset);
	if((rbytes = fread((void *)dest, elf->phdr[j].p_filesz, 1, elf->fp)) != 1)
	    fatal("file read failure, rbytes = %ld, filesz = 0x%08lX \n",
		  rbytes,
		  elf->phdr[j].p_filesz);

	//printf("LOAD: vaddr = %08llX\n", elf->phdr[j].p_vaddr + elf->phdr[j].p_filesz - 32);
	//phex(dest + elf->phdr[j].p_filesz - 32, 32);
	// need to copy the data now
    }
    
}

void fini_elf64_file(struct elf64_file *elf)
{
    int i;
    fclose(elf->fp);
    elf->file_status = enum_close;
    free(elf->phdr);
    for(i = 0; i < elf->num_regions; i++) {
	munmap(elf->prog_regions[i]->addr,
	       elf->prog_regions[i]->num_pages * PAGE_SIZE);
	free(elf->prog_regions[i]);
    }
    free(elf->prog_regions);
}


