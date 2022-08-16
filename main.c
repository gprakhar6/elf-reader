#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>

#define MAX_LEN_FILENAME (128)
#define MAX_INPUT_SZ (64)
#define NUM_INPUT_FIELDS (3)
#define MAX_SPEC_SZ (8)
#define MAX_INP_READ_SZ (3)

#define fatal(s, ...) do {printf("%04d: ", __LINE__); printf(s, ##__VA_ARGS__); exit(1);} while(0)
#define GEN_LMT(t, v, l, h) ((*(t *)v >= *(t *)l) && (*(t *)v <= *(t *)h))

#define ADD2DSTR(s, i) (&s[i][0])

enum file_status {
    enum_open = 0,
    enum_close
};
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

struct elf64_file {
    char fname[MAX_LEN_FILENAME];
    FILE *fp;
    enum file_status file_status;
    unsigned long file_size;
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr;
    void (*print_elf_hdr)(struct elf64_file *elf);
};
const char optstring[] = "f:";
const char default_file[] = "main";
const char limit_default_file[] = "limits.txt";
const char str_limit_t[limits_t_sz][128] =
{
    "ephdr",
    "eshdr",
};
const char inp_read_str[limits_t_sz][MAX_INP_READ_SZ] =
{
    [ephdr] = "%d",
    [eshdr] = "%d",
};

void init_elf64_file(char filename[MAX_LEN_FILENAME],
		     struct elf64_file *elf);

int within_lmts(void *v, enum data_t type, struct limits *l);
void init_limits(char limit_file[MAX_LEN_FILENAME]);

struct limits limits[limits_t_sz];

int main(int argc, char *argv[])
{
    int ret;
    char filename[MAX_LEN_FILENAME], limit_filename[MAX_LEN_FILENAME];
    unsigned char file_name_pasd, limit_file_pasd;
    struct elf64_file elf;
    
    file_name_pasd = 0;
    limit_file_pasd = 0;
    while((ret = getopt(argc, argv, optstring)) != -1) {
	switch(ret) {
	case 'f':
	    file_name_pasd = 1;
	    strncpy(filename, optarg, sizeof(filename));
	    printf("File is = %s\n", filename);
	    break;
	case 'l':
	    limit_file_pasd = 1;
	    strncpy(limit_filename, optarg, sizeof(limit_filename));
	    printf("limit file is %s\n", limit_filename);
	    break;
	case '?':
	    printf("unknown option %c\n", optopt);
	    break;
	default:
	    fatal("opt character not found\n");
	}
    }

    if(file_name_pasd == 0) {
	strncpy(filename, default_file, sizeof(filename));
	printf("using default file(%s) as file name not passed using -f\n", default_file);
    }

    if(limit_file_pasd == 0) {
	strncpy(limit_filename, limit_default_file, sizeof(limit_filename));
	printf("using default file(%s) as limit file name not passed using -l\n", limit_default_file);	
    }

    init_limits(limit_filename);
    //read_elf_hdr(filename, &elf);
    //print_elf_hdr(&elf);

    init_elf64_file(filename, &elf);

    elf.print_elf_hdr(&elf);
    return 0;
}

int within_lmts(void *v, enum data_t type, struct limits *l)
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

void init_limits(char limit_file[MAX_LEN_FILENAME])
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
}

void read_elf64_file(struct elf64_file *elf)
{
    if(elf->file_status == enum_close)
	fatal("Trying to read closed file %s\n", elf->fname);

    fseek(elf->fp, 0, SEEK_SET);
    fread(&elf->ehdr, sizeof(elf->ehdr), 1, elf->fp);

    if(elf->ehdr.e_phoff >= elf->file_size)
	fatal("wrong phoff, phoff= %lu, file size = %lu\n",
	      elf->ehdr.e_phoff, elf->file_size);
}

void init_elf64_file(char filename[MAX_LEN_FILENAME],
		     struct elf64_file *elf) {

    int i;
    uint16_t phentsize, phnum;
    Elf64_Off phoff;
    
    strncpy(elf->fname, filename, sizeof(elf->fname));

    elf->fp = fopen(elf->fname, "r");
    if(elf->fp == NULL)
	fatal("unable to open %s", elf->fname);

    elf->file_status = enum_open;

    fseek(elf->fp, 0, SEEK_END);
    elf->file_size = ftell(elf->fp);
    read_elf64_file(elf);
    elf->print_elf_hdr = print_elf_hdr_64;

    phoff = elf->ehdr.e_phoff;
    phentsize = elf->ehdr.e_phentsize;
    phnum = elf->ehdr.e_phnum;

    if(!within_lmts(&phentsize, ephdr, &limits[ephdr]))
	fatal("phdrsz not within limits. phdrsz = 0x%04X\n", phentsize);

    elf->phdr = (Elf64_Phdr *)calloc(phnum, sizeof(Elf64_Phdr));
    if(elf->phdr == NULL)
	fatal("could not allocate %d of %ld bytes\n", phnum, sizeof(Elf64_Phdr));
    fread(elf->phdr, sizeof(Elf64_Phdr), phnum, elf->fp);

    
}


