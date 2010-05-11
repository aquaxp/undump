#include "program.h"
#include "core.h"
#include "elfcommon.h"

#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>


struct program *prog_read_elf(const char *filename)
{
    struct program *p = malloc(sizeof (struct program));
    struct stat buf;
    int fd = -2;

    if (!p) /* TODO: Add proper error reporting */
        goto error;

    fd = open(filename, O_RDONLY);
    if(fd < 0) 
        goto error;

    p->fd = fd;

    if (fstat(fd, &buf) < 0)
        goto error;

    p->size = buf.st_size;
    p->prog = (char *)mmap(NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p->prog == MAP_FAILED) 
        goto error;
   
    p->header = (Elf32_Ehdr *)p->prog;
    return p;

error:
    if(p)
        free(p);
    if(fd >= 0)
        close(fd);
    return NULL;    
}


Elf32_Phdr *prog_get_program_headers(struct program *p)
{
    return elf_get_program_headers(p->prog);
}

Elf32_Shdr *prog_get_sections(struct program *p)
{
    return elf_get_sections(p->prog);
}

char *prog_get_section_name(struct program *p, Elf32_Shdr *s)
{
    return elf_get_section_name(p->prog, s);
}

void dump_program_data(struct program *p)
{
    int i;
    Elf32_Phdr *ph;
    Elf32_Shdr *s;

    char str[256];

    printf("Program: %p\n", p);
    printf("ELF Type: %d, Flags: %x, Entry: %p\n", p->header->e_type, p->header->e_flags , p->header->e_entry);
    printf("ELF Id: %c%c%c%c\n", p->header->e_ident[0], p->header->e_ident[1], p->header->e_ident[2],
        p->header->e_ident[3]);

    printf("Program Headers: %d\n", p->header->e_phnum);
    for (i=0; i < p->header->e_phnum; i++) {
        ph = &(prog_get_program_headers(p)[i]);
        printf("\tProgram Header: Type: %p Off: %p Allign: %p VAddr: %p FSize: %d MemSize: %d\n", 
                ph->p_type, ph->p_offset, ph->p_align, ph->p_vaddr, ph->p_filesz, ph->p_memsz); 
    }

    printf("\n\nSections: %d\n", p->header->e_shnum);
    for (i=1; i < p->header->e_shnum; i++) {
        s = &(prog_get_sections(p)[i]);
        printf("\tSection: Name \"%s\"\n", prog_get_section_name(p, s));
    }
}

