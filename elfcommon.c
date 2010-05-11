#include "core.h"
#include "program.h"
#include "elf.h"

#include "elfcommon.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

Elf32_Shdr *elf_get_sections(char *c)
{
    Elf32_Ehdr *header = (Elf32_Ehdr *)c;

    assert(sizeof(Elf32_Shdr) == header->e_shentsize);
    return (Elf32_Shdr *)&c[header->e_shoff];
}

char *elf_get_section_strings(char *c)
{
    Elf32_Ehdr *header = (Elf32_Ehdr *)c;

    Elf32_Shdr *sh = &elf_get_sections(c)[header->e_shstrndx];
    return &c[sh->sh_offset];
}

char *elf_get_section_name(char *c, Elf32_Shdr *s)
{
    char *str = elf_get_section_strings(c);
    return &str[s->sh_name];
}

Elf32_Phdr *elf_get_program_headers(char *c)
{
    Elf32_Ehdr *header = (Elf32_Ehdr *)c;

    assert(sizeof(Elf32_Phdr) == header->e_phentsize);
    return (Elf32_Phdr *)&c[header->e_phoff];
}

undumped_program *elf_new_undumped_program()
{
    undumped_program *p = malloc(sizeof(*p));
    memset(p, 0, sizeof(*p));

    p->ehdr.e_ident[0] = ELFMAG0;
    p->ehdr.e_ident[1] = ELFMAG1;
    p->ehdr.e_ident[2] = ELFMAG2;
    p->ehdr.e_ident[3] = ELFMAG3;

    p->ehdr.e_ident[EI_CLASS] = ELFCLASS32;
    p->ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    p->ehdr.e_ident[EI_VERSION] = EV_CURRENT;

    p->ehdr.e_phentsize = sizeof(Elf32_Phdr);
    p->ehdr.e_phoff = sizeof(Elf32_Ehdr);
    p->ehdr.e_type = ET_EXEC;
    p->ehdr.e_version = EV_CURRENT;
    p->ehdr.e_machine = EM_386;
    p->ehdr.e_ehsize = sizeof(p->ehdr);

    return p;
}

/**
 * Add a segment to the undumped_program object p. phdr is a Program Header object with the information
 * needed. The field that isn't used from the phdr is the offset, since it changes according to the
 * program. Also, if the code_seg flag parameter is set (!=0) then the segment will be considered as the
 * first segment in the executable. This means that the offset of this segment will be set to 0, as 
 * expected from a code segment (it contains the entire ELF usually). Also, the content will not be copied
 * directly. It will be copied only from the entry point of the old code.
 * TODO: Is this ok?
 */

undump_segment *elf_add_segment(undumped_program *p, char *content, Elf32_Phdr *phdr)// int code_seg)
{
    /* Will add a segment as and a relevant program header 
     * If content is NULL, then we don't copy its content and we won't touch its offset later too */
    undump_segment *seg;

    (p->ehdr.e_phnum)++;
    p->segments = realloc(p->segments, p->ehdr.e_phnum * sizeof(undump_segment));
    seg = &p->segments[p->ehdr.e_phnum - 1];
    memcpy(&seg->phdr, phdr, sizeof(undump_segment));
    
    if(content) { /* If content is NULL, we aren't copying anything... */
        seg->segment = malloc(seg->phdr.p_filesz);
        memcpy(seg->segment, content, seg->phdr.p_filesz);
    } else {
        seg->segment = NULL;
    }
    seg->phdr.p_paddr = seg->phdr.p_vaddr;

    return seg;
}

uint32_t elf_get_nextvaddr(undumped_program *p)
{
    uint32_t vaddr = 0, align = 0;
    int i;
    
    for (i=0; i < p->ehdr.e_phnum; i++) {
        if(p->segments[i].phdr.p_vaddr + p->segments[i].phdr.p_memsz > vaddr) {
            vaddr = p->segments[i].phdr.p_vaddr + p->segments[i].phdr.p_memsz;
            align = p->segments[i].phdr.p_align;
        }
    }
    return (vaddr - (vaddr % align) + align);
}








