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
#include <string.h>


struct core *load_core(char *filename)
{
    struct core *c = malloc(sizeof (struct core));
    struct stat buf;
    int fd = -2;

    if (!c) /* TODO: Add proper error reporting */        
        goto error;

    fd = open(filename, O_RDONLY);
    if(fd < 0) 
        goto error;

    c->fd = fd;

    if (fstat(fd, &buf) < 0)
        goto error;
    
    c->size = buf.st_size;
    c->core = (char *)mmap(NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (c->core == MAP_FAILED) 
        goto error;
   

    if (!core_parse_core(c, c->core))
        goto error;

    return c;
error:
    if(c)
        free(c);
    if(fd >= 0)
        close(fd);
    return NULL;    
}

Elf32_Phdr *core_get_program_headers(struct core *c)
{
    assert(sizeof(Elf32_Phdr) == c->header->e_phentsize);
    return (Elf32_Phdr *)&c->core[c->header->e_phoff];
}

static
int _core_read_note(struct core *c)
{
    /* The first note in the core file is supposed to be the program status. */
    Elf32_Phdr *ph = core_get_program_headers(c);
    Elf32_Nhdr *nh;
    char *segment, *s;

    segment = &c->core[ph->p_offset];
    nh = (Elf32_Nhdr *)segment;
    if(nh->n_type != NT_PRSTATUS) /* Not a core?? */
        return 0;
    if(memcmp(&segment[sizeof(*nh)], CORE_MAGIC, 8)) /* Should be CORE\0\0\0\0 */
        return 0;
    if(nh->n_descsz != sizeof(prstatus))
        return 0;
    s = &segment[sizeof(*nh) + 8];
    c->status = (prstatus *)s;

    /*TODO: FPU registers */
    return 1;    
}

int core_parse_core(struct core *c, char *data)
{
    c->header = (Elf32_Ehdr *)c->core; /* header is the first data in the ELF */
    c->core = data;

    if (!_core_read_note(c))
        return 0;
    return 1;
}

Elf32_Shdr *core_get_sections(struct core *c)
{
    return elf_get_sections(c->core);
}

char *core_get_section_strings(struct core *c)
{
    return elf_get_section_strings(c->core);
}

char *core_get_section_name(struct core *c, Elf32_Shdr *s)
{
    return elf_get_section_name(c->core, s);
}

prstatus *core_get_status(struct core *c)
{
    return c->status;
}

void dump_core_data(struct core *c)
{
    int i;
    /* Print core data to stdout... */
    Elf32_Phdr *p;
    Elf32_Shdr *s;
    prstatus *pr = c->status;

    printf("Core: %p\n", c);
    printf("ELF Type: %d\n", c->header->e_type);
    printf("ELF Id: %c%c%c%c\n", c->header->e_ident[0], c->header->e_ident[1], c->header->e_ident[2],
        c->header->e_ident[3]);

    printf("Program Status: pid = %d, ppid = %d, pgrp = %d, sid = %d, \n", pr->pr_pid, 
            pr->pr_ppid, pr->pr_pgrp, pr->pr_sid);
    printf("Some regs: BP = %p, SP = %p, IP = %p\n", pr->pr_reg.BP, pr->pr_reg.SP, pr->pr_reg.IP);
    
    printf("Program Headers: %d\n", c->header->e_phnum);
    for (i=0; i < c->header->e_phnum; i++) {
        p = &(core_get_program_headers(c)[i]);
        printf("\tProgram Header: Type: 0x%x Off: 0x%x Allign: 0x%x VAddr: %x\n", p->p_type, p->p_offset,
               p->p_align, p->p_vaddr); 
    }

    printf("\n\nSections: %d\n", c->header->e_shnum);
    for (i=0; i < c->header->e_shnum; i++) {
        s = &(core_get_sections(c)[i]);
        printf("\tSection: Name \"%s\"\n", core_get_section_name(c, s)
                );
    }
}
