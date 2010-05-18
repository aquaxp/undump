#ifndef __ELF_COMMON_H__
#define __ELF_COMMON_H__


#include <elf.h>


typedef struct {
    Elf32_Phdr phdr;
    char *segment;
} undump_segment;

typedef struct {
    Elf32_Ehdr ehdr;
    undump_segment *segments;
} undumped_program;

Elf32_Shdr *elf_get_sections(char *c);
char *elf_get_section_strings(char *c);
char *elf_get_section_name(char *c, Elf32_Shdr *s);
Elf32_Phdr *elf_get_program_headers(char *c);

/* Methods to manipulate the undumped_program struct */

undump_segment *elf_add_segment(undumped_program *und, char *segment, Elf32_Phdr *phdr);
undumped_program *elf_new_undumped_program();
uint32_t elf_get_nextvaddr(undumped_program *p);

#define elf_get_elf_header(c) ((Elf32_Ehdr*)c)

#endif
