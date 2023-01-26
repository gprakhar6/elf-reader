#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <elf.h>

#include "elf-reader.h"

#define fatal(s, ...) do {printf("%s.%04d: ", __FILE__,__LINE__); printf(s, ##__VA_ARGS__); exit(1);} while(0)
#define GEN_LMT(t, v, l, h) ((*(t *)v >= *(t *)l) && (*(t *)v <= *(t *)h))
#define ADD2DSTR(s, i) (&s[i][0])

enum limits_t {
    ephdr = 0,
    eshnum,
    eshdrentsize,
    limits_t_sz
};

enum data_t {
    euint16_t = 0,
    data_t_sz
};

struct limits {
    unsigned char spec[NUM_INPUT_FIELDS][MAX_SPEC_SZ];
    //enum data_t type;
};

static const char elf_mag[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
static const char str_limit_t[limits_t_sz][128] =
{
    "ephdr",
    "eshnum",
    "eshdrentsize",
};
static const char inp_read_str[limits_t_sz][MAX_INP_READ_SZ] =
{
    [ephdr] = "%d",
    [eshnum] = "%d",
    [eshdrentsize] = "%d",
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

static struct limits __attribute__((aligned(8))) limits[limits_t_sz];

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

    if((type < 0) || (type >= data_t_sz))
	fatal("wrong data type\n");

    switch(type) {
    case euint16_t:
	if(GEN_LMT(uint16_t, v, ADD2DSTR(l->spec, 0), ADD2DSTR(l->spec, 1)))
	    in_lmt = 1;
	else {
	    printf("!(%d <= %d <= %d)\n",
		   *(uint16_t *)ADD2DSTR(l->spec, 0),
		   *(uint16_t *)v,
		   *(uint16_t *)ADD2DSTR(l->spec, 1));
	}
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
	printf("%02X ", elf->ehdr->e_ident[i]);
    }
    printf("\n");

    for(i = 0; i < elf->ehdr->e_phnum; i++) {
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
    uint16_t phentsize, phnum, shentsize, shnum, shstrndx;
    Elf64_Off phoff, shoff;
    Elf64_Shdr *shdr;
    strncpy(elf->fname, filename, sizeof(elf->fname));
    elf->fp = fopen(elf->fname, "r");
    if(elf->fp == NULL)
	fatal("unable to open %s", elf->fname);
    elf->fd = fileno(elf->fp);
    if(elf->fd == -1)
	fatal("fileno failed, returned probably -1\n");
    elf->file_status = enum_open;
    if(fstat(elf->fd, &elf->stat))
	fatal("error in fstat\n");
    elf->mm = mmap(NULL, elf->stat.st_size, PROT_READ, \
		   MAP_SHARED, elf->fd, 0);

    if(elf->mm == NULL)
	fatal("elf mmap failed\n");

    // check for magic word
    for(i = 0; i < 4; i++)
	if(((char *)elf->mm)[i] != elf_mag[i])
	    fatal("%s in not elf file, %02X, %02X\n", elf->fname,
		  ((char *)elf->mm)[i], elf_mag[i]);
    
    //printf("first elf = %08lX\n", *((uint64_t *)elf->mm));
    fseek(elf->fp, 0, SEEK_END);
    elf->file_size = elf->stat.st_size;

    if(elf->file_status == enum_close)
	fatal("Trying to read closed file %s\n", elf->fname);

    elf->ehdr = (Elf64_Ehdr *)elf->mm;
    if(elf->ehdr->e_phoff >= elf->file_size)
	fatal("wrong phoff, phoff= %lu, file size = %lu\n",
	      elf->ehdr->e_phoff, elf->file_size);
    elf->print_elf_hdr = print_elf_hdr_64;

    phoff = elf->ehdr->e_phoff;
    phentsize = elf->ehdr->e_phentsize;
    phnum = elf->ehdr->e_phnum;

    if(!within_lmts(&phentsize, euint16_t, &limits[ephdr])) {
	fatal("phdrsz not within limits. phdrsz = 0x%04X\n", phentsize);
    }

    elf->phdr = (Elf64_Phdr *)((uint64_t)elf->mm + (uint64_t)sizeof(*(elf->ehdr)));
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
	elf->prog_regions[i]->offset    = elf->phdr[j].p_offset;
	elf->prog_regions[i]->type      = elf->phdr[j].p_type;
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
	elf->prog_regions[i]->addr = (void *)((uint64_t)(elf->mm) + (uint64_t)(elf->phdr[j].p_offset));
    }

    {
	shoff		= elf->ehdr->e_shoff;
	shentsize	= elf->ehdr->e_shentsize;
	shnum		= elf->ehdr->e_shnum;
	shstrndx	= elf->ehdr->e_shstrndx;
	if(!within_lmts(&shentsize, euint16_t, &limits[eshdrentsize]))
	    fatal("shdrentsize not within limits. shdrentsize = 0x%04X\n", shentsize);

	if(shstrndx < 0 || shstrndx >= shnum)
	    fatal("shstrndx not in table range");

	if(!within_lmts(&shnum, euint16_t, &limits[eshnum]))
	    fatal("shnum not within limits. shnum = 0x%04X\n", shnum);
	
	if(shentsize != sizeof(Elf64_Shdr))
	    fatal("shentsize != sizeof(Elf64_Shdr), sth is fishy\n");

	elf->shdr = (Elf64_Shdr *)((uint64_t)(elf->mm) + (uint64_t)(shoff));
	elf->shstrtbl_size = elf->shdr[shstrndx].sh_size;
	elf->shstrtbl = (char *)((uint64_t)(elf->mm) + (uint64_t)(elf->shdr[shstrndx].sh_offset));
	shdr = get_shdr(elf, ".dynsym");
	if(shdr != NULL) {
	    elf->dynsyms_size = (shdr->sh_size) / (shdr->sh_entsize);
	    elf->dynsyms = (typeof(elf->dynsyms))((uint64_t)(elf->mm) + (uint64_t)(shdr->sh_offset));
	}
	else {
	    elf->dynsyms_size = 0;
	    elf->dynsyms = NULL;
	}
	shdr = get_shdr(elf, ".dynstr");
	if(shdr != NULL) {
	    elf->dynstrtbl_size = shdr->sh_size;
	    elf->dynstrtbl = (typeof(elf->dynstrtbl))((uint64_t)(elf->mm) + (uint64_t)(shdr->sh_offset));
	} else {
	    elf->dynstrtbl_size = 0;
	    elf->dynstrtbl = NULL;
	}
	// TBD what about .rel.dyn? how to handle?
	shdr = get_shdr(elf, ".rela.dyn");
	if(shdr != NULL) {
	    elf->rela_size = (shdr->sh_size) / (shdr->sh_entsize);
	    elf->rela = (typeof(elf->rela))((uint64_t)(elf->mm) + (uint64_t)(shdr->sh_offset));
	}
	else {
	    elf->rela_size = 0;
	    elf->rela = NULL;
	}

	shdr = get_shdr(elf, ".dynamic");
	if(shdr != NULL) {
	    elf->dynamic_size = (shdr->sh_size) / (shdr->sh_entsize);
	    elf->dynamic = (typeof(elf->dynamic))((uint64_t)(elf->mm) + (uint64_t)(shdr->sh_offset));
	}
	else {
	    elf->dynamic_size = 0;
	    elf->dynamic = NULL;
	}
	
	shdr = get_shdr(elf, ".strtab");
	if(shdr != NULL) {
	    elf->strtbl_size = (shdr->sh_size);
	    elf->strtbl = (typeof(elf->strtbl))((uint64_t)(elf->mm) + (uint64_t)(shdr->sh_offset));
	}
	else {
	    elf->strtbl_size = 0;
	    elf->strtbl = NULL;
	}
	
#if 0	
	for(i = 0; i < shnum; i++) {
	    int idx;
	    idx = elf->shdr[i].sh_name;
	    if(strcmp(&elf->shdrtbl[idx], ".stack") == 0) {
		printf("match exist in %d\n", i);
	    }
	}
#endif	
    }
    
}

void fini_elf64_file(struct elf64_file *elf)
{
    int i;
    fclose(elf->fp);
    elf->file_status = enum_close;
    //free(elf->phdr);
    //free(elf->shdr);
    //free(elf->shstrtbl);
    for(i = 0; i < elf->num_regions; i++) {
	/*
	munmap(elf->prog_regions[i]->addr,
	       elf->prog_regions[i]->num_pages * PAGE_SIZE);
	*/
	free(elf->prog_regions[i]);
    }
    free(elf->prog_regions);
}
// utility funcs
/****************************************************/

Elf64_Shdr* get_shdr(struct elf64_file *elf, char *name)
{
    int i;
    Elf64_Shdr *ret = NULL;

    for(i = 0; i < elf->ehdr->e_shnum; i++) {
	int idx;
	idx = elf->shdr[i].sh_name;
	if(strcmp(&(elf->shstrtbl[idx]), name) == 0) {
	    //printf("idx = %d\n", i);
	    ret = &(elf->shdr[i]);
	    break;
	}
    }

    return ret;
}

// start iteration by passing ct = 0. Subsequent call
// with elf and &ct
Elf64_Shdr* iterate_shdr(struct elf64_file *elf, int *ct)
{
    if((*ct < elf->ehdr->e_shnum) && *ct >= 0) {
	(*ct)++;
	return &(elf->shdr[*ct]);
    }
    return NULL;
}

// ret
Elf64_Sym* dynsym_l0(Elf64_Sym *syms, int sz,
			  char *dynstr, char name[])
{
    int i, idx;
    Elf64_Sym *sym = (Elf64_Sym *)-1;
    for(i = 0; i < sz; i++) {
	idx = syms[i].st_name;
	if(idx != 0) {
	    if(strcmp(name, &dynstr[idx]) == 0) {
		sym = &syms[i];
		break;
	    }
	}
    }
    return sym;
}

Elf64_Sym* dynsym(struct elf64_file *elf, char name[])
{
    return dynsym_l0(elf->dynsyms, elf->dynsyms_size,
		     elf->dynstrtbl, name);
}

char *dynsym_name(Elf64_Sym *sym, char *dynstrtbl) {
    return &(dynstrtbl[sym->st_name]);
}

// iterate over rel symbols
int iterate_rel(struct elf64_file *elf, relocs_t *rel, int *idx)
{
    int i, dynidx;
    Elf64_Rela *rela;
    Elf64_Sym *sym;
    if(idx == NULL)
	return -1;
    i = *idx;
    if(!(i >= 0 && i < elf->rela_size) || (rel == NULL))
	return -1;
    rela = &(elf->rela[i]);

    rel->offset = rela->r_offset;
    rel->type = ELF64_R_TYPE(rela->r_info);
    dynidx = ELF64_R_SYM(rela->r_info);
    sym = &(elf->dynsyms[dynidx]);
    rel->sym_value = sym->st_value;
    rel->sz = sym->st_size;
    rel->name = dynsym_name(sym, elf->dynstrtbl);
    rel->addend = rela->r_addend;
    
    return (*idx)++;
}
static const char sym_type[][64] = {
    [0] = "R_X86_64_NONE",           
    [1] = "R_X86_64_64",             
    [2] = "R_X86_64_PC32",           
    [3] = "R_X86_64_GOT32",          
    [4] = "R_X86_64_PLT32",          
    [5] = "R_X86_64_COPY",           
    [6] = "R_X86_64_GLOB_DAT",       
    [7] = "R_X86_64_JUMP_SLOT",      
    [8] = "R_X86_64_RELATIVE",       
    [9] = "R_X86_64_GOTPCREL",       
    [10] = "R_X86_64_32",             
    [11] = "R_X86_64_32S",            
    [12] = "R_X86_64_16",             
    [13] = "R_X86_64_PC16",           
    [14] = "R_X86_64_8",              
    [15] = "R_X86_64_PC8",
    [16 ... 23] = "",
    [24] = "R_X86_64_PC64",
};
void print_relocs(struct elf64_file *elf)
{
    int idx;
    relocs_t rel;
    idx = 0;
    printf("%-16s %-16s %-16s %-4s %-4s %-16s\n",
	   "name", "offset", "sym_value", "sz",
	   "adnd", "sym_type");
    while(iterate_rel(elf, &rel, &idx) != -1){
	printf("%-16s %016lX %016lX %04ld %04ld %-16s\n",
	       rel.name, rel.offset, rel.sym_value, rel.sz,
	       rel.addend, &sym_type[rel.type][0]);
    }
    printf("\n");
}

int iterate_needed_libs(struct elf64_file *elf, char **name, int *idx)
{
    int i, ret;
    Elf64_Dyn *dyn;
    if(idx == NULL)
	return -1;
    i = *idx;
    if(!(i >= 0 && i < elf->dynamic_size))
	return -1;

    ret = -1;
    while(i < elf->dynamic_size) {
	dyn = &(elf->dynamic[i]);
	if (dyn->d_tag == DT_NEEDED) {
	    *name = &(elf->dynstrtbl[dyn->d_un.d_val]);
	    i++;
	    *idx = ret = i;
	    break;
	}
	i++;
    }
    
    return ret;
}

void print_needed_libs(struct elf64_file *elf)
{
    char *name;
    int idx;
    idx = 0;
    while(iterate_needed_libs(elf, &name, &idx) != -1) {
	printf("%s, ", name);
    }
    printf("\n");
}
