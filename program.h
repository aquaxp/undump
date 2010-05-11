#ifndef __PROGRAM_H__
#define __PROGRAM_H__

#include <elf.h>
#include <unistd.h>
#include <sys/types.h>


struct program {
    Elf32_Ehdr *header;
    char *prog;
    int fd;
    off_t size;
};


struct program *prog_read_elf(const char *filename);

Elf32_Phdr *prog_get_program_headers(struct program *p);
Elf32_Shdr *prog_get_sections(struct program *p);
char *prog_get_section_name(struct program *p, Elf32_Shdr *s);
void dump_program_data(struct program *p);

#endif

