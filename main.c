#include <stdio.h>

#include "elf-reader.h"

static const char optstring[] = "f:l:";
static const char default_file[] = "main";
static const char limit_default_file[] = "limits.txt";

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
	    printf("unknown flag");
	    exit(-1);
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
    
    fini_elf64_file(&elf);
    
    return 0;
}
