#include <stdio.h>

#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "core.h"
#include "program.h"
#include "elfcommon.h"
#include <assert.h>
#include <sys/user.h>

#define PAGE_ALIGN(x) ((off) + PAGE_SIZE) & PAGE_MASK;
#define PATH_MAX 1023


/* There are several ways to create the undump code to restore the registers.
 * Generating the code would require the following. However, it's very static, 
 * so a static approach is simpler. In any case, if a non-static approach would
 * be used, the following code could help:

const char *UNDUMP_ASM_TMPL[] = {
    ".text\n.globl _undump_start\n_undump_start:\n\tmovl $0x%x, %%ebx\n",
    "\tmovl $0x%x, %%ecx\n",
    "\tmovl $0x%x, %%edx\n",
    "\tmovl $0x%x, %%esi\n",
    "\tmovl $0x%x, %%edi\n",
    "\tmovl $0x%x, %%ebp\n",
    "\tmovl $0x%x, %%eax\n",
    "\tmovl $0x%x, %%esp\n",
    "\tpushl $0x%x\n\tret",
    NULL
};

 combine this const with the code:

static
char * _undump_get_asm_src(struct core *c)
{
    int len, i;
    char *src = NULL, *l;
    prstatus *status = core_get_status(c);
    regs *r = &status->pr_reg;

    const uint32_t reg[] = {
      r->ebx, r->ecx, r->edx, r->esi, r->edi, r->ebp, r->eax,
      r->esp,
      r->eip
    };
    
    src = malloc(1);
    src[0] = 0;
    for(i=0; UNDUMP_ASM_TMPL[i]; i++) {
        len = strlen(UNDUMP_ASM_TMPL[i]) + 1 + sizeof(void*)*2; 
        l = malloc(len);
        snprintf(l, len, UNDUMP_ASM_TMPL[i], reg[i]);
        src = realloc(src, (src ? strlen(src) : 0) + len + 1);
        if(!src) {
            free(src);
            return NULL;
        }
        strcat(src, l);
        free(l);
    }
    return src;
}
 */

/*struct undump_machine_code {
    uint8_t mov_ebx;
    uint32_t ebx;
    uint8_t mov_ecx;
    uint32_t ecx;
    uint8_t mov_edx;
    uint32_t edx;
    uint8_t mov_esi;
    uint32_t esi;
    uint8_t mov_edi;
    uint32_t edi;
    uint8_t mov_ebp;
    uint32_t ebp;
    uint8_t mov_eax;
    uint32_t eax;
    uint8_t mov_esp;
    uint32_t esp;
    uint8_t pushl;
    uint32_t eip;
    uint32_t ret;
};*/

struct options {
    char core_file_name[256];
    char program_file_name[256];
    char new_file[256];
};

int _get_options(int argc, char **argv, struct options *op)
{
    if(argc < 4)
        return 0;
    strncpy(op->core_file_name, argv[1], sizeof(op->core_file_name));
    strncpy(op->program_file_name, argv[2], sizeof(op->program_file_name));
    strncpy(op->new_file, argv[3], sizeof(op->new_file));

    return 1;
}

#define ADD_INSTRUCTION_L(data, inst, what) do {\
    uint8_t tmp_inst_var = inst;\
    memcpy((data)++, &(tmp_inst_var), 1);\
    memcpy((data), &(what), sizeof(what));\
    data+=sizeof(what);\
} while(0)

#define ADD_LOAD_AX(data, what) do {\
    uint16_t tmp_inst_var = 0xb866;\
    memcpy((data), &tmp_inst_var, sizeof(uint16_t));\
    data += 2;\
    memcpy((data), &(what), sizeof(uint16_t));\
    data += 2;\
} while(0)

#define ADD_INSTRUCTION_W(data, inst) do {\
    uint16_t tmp_inst_var = (inst);\
    memcpy((data), &tmp_inst_var, sizeof(uint16_t));\
    data += 2;\
} while(0)

static
char *_undump_get_machine_code(int size, struct core *c)
{   
    prstatus *st = core_get_status(c);
    regs *r = &st->pr_reg;
    char *data = malloc(size), *start;
    uint32_t tmp;
    uint16_t flags;
    
    start = data;

    ADD_LOAD_AX(data, r->ss);
    printf("ss = %x, ", r->ss);

    ADD_INSTRUCTION_W(data, 0xd08e);
    ADD_LOAD_AX(data, r->ds);
    printf("ds = %x, ", r->ds);
    
    ADD_INSTRUCTION_W(data, 0xd88e);
    ADD_LOAD_AX(data, r->es);
    printf("es = %x, ", r->es);
    
    ADD_INSTRUCTION_W(data, 0xc08e);
    ADD_LOAD_AX(data, r->fs);
    printf("fs = %x, ", r->fs);
    
    ADD_INSTRUCTION_W(data, 0xe08e);
    ADD_LOAD_AX(data, r->gs);
    printf("gs = %x\n", r->gs); 

    ADD_INSTRUCTION_L(data, 0xbb, r->ebx); /*movl to registers */
    ADD_INSTRUCTION_L(data, 0xb9, r->ecx);
    ADD_INSTRUCTION_L(data, 0xba, r->edx);
    ADD_INSTRUCTION_L(data, 0xbe, r->esi);
    ADD_INSTRUCTION_L(data, 0xbf, r->edi);
    ADD_INSTRUCTION_L(data, 0xbd, r->ebp);
    ADD_INSTRUCTION_L(data, 0xb8, r->eax);
    ADD_INSTRUCTION_L(data, 0xbc, r->esp);

    ADD_INSTRUCTION_L(data, 0x68, r->eflags); /*pushl to return to previous location*/
    *(data++) = 0x9d;

    ADD_INSTRUCTION_L(data, 0x68, r->eip); /*pushl to return to previous location*/
    
    ADD_INSTRUCTION_L(data, 0xc3, tmp); 

    return start;
}

uint32_t undump_add_restore_seg(undumped_program *prog, struct core *c)
{
    /* There are several ways to do this. One being the automatic generation of assembly
     * file to do that and then compiling it, however, this would require an assembler
     * present. Instead, a simpler approach can be used, simply write the exact machine code...
     */
    
    Elf32_Phdr phdr;
    char *machine_code;
    int size = 256; /* should be more than enough */ 

    memset(&phdr, 0, sizeof(phdr));
    
    machine_code = _undump_get_machine_code(size, c);

    phdr.p_vaddr = elf_get_nextvaddr(prog);
    phdr.p_filesz = size;
    phdr.p_flags = PF_R | PF_X;
    phdr.p_memsz = phdr.p_filesz;
    phdr.p_align = PAGE_SIZE;
    phdr.p_type = PT_LOAD;

    elf_add_segment(prog, machine_code, &phdr);
    printf("Undump code segment at %p\n", (void*)phdr.p_vaddr);

    return phdr.p_vaddr;
}

int undump_copy_phs(undumped_program *prog, struct core *c, struct program *p)
{
    int i, j, num_copied = 0, do_copy = 0;
    Elf32_Ehdr *c_header = elf_get_elf_header(c->core);
    Elf32_Ehdr *p_header = elf_get_elf_header(p->prog);
    Elf32_Phdr *phs, *chs;
    char *data;

    phs = elf_get_program_headers(p->prog);
    chs = elf_get_program_headers(c->core);

    /* The core does NOT contain the code but it contains a segment
     * where the code resided. This segment has to be copied from the executable.
     * First order of business then is to copy all the program headers in the executable that have
     * the "PT_LOAD" flag and are not writable. Those do not have to be copied to the core. */

    data = p->prog; /* just for short-hand */
    for(i=0; i<p_header->e_phnum ;i++) {
        if(phs[i].p_type == PT_LOAD && !(phs[i].p_flags&PF_W)) {
            elf_add_segment(prog, &data[phs[i].p_offset], &phs[i]);
            num_copied++;
        }
    }
    data = c->core;
    for(i=0; i<c_header->e_phnum; i++) {
        do_copy = 1;
        for (j=0; j<num_copied; j++) {
            /* Find out if there's an overlap. There has to be some. The code segment
             * is also marked for LOAD in the core file, but contains no code. */
            if(chs[i].p_type != PT_LOAD || prog->segments[j].phdr.p_vaddr == chs[i].p_vaddr)
                do_copy = 0;
        }
        if(do_copy) {
            elf_add_segment(prog, &data[chs[i].p_offset], &chs[i]);
        }
    }

    return 1;
}

int undump_write_undumped(int fd, undumped_program *p)
{
    int i;
    off_t off;

    off = p->ehdr.e_phoff + (p->ehdr.e_phnum) * sizeof(Elf32_Phdr); 
    off = PAGE_ALIGN(off);
    
    if(lseek(fd, off, SEEK_SET) < 0) /* For some unknown (to me) reason the offset has to be page aligned... */
        return 0;

    /* First, write the content of the segments, and only then write the headers. 
     * It's easier to calculate the offsets this way... */

    for(i=0; i < p->ehdr.e_phnum; i++) { 
        printf("Writing segment with offset 0x%x, vaddr %p...", p->segments[i].phdr.p_offset, 
                (void*)p->segments[i].phdr.p_vaddr);

        if (!p->segments[i].segment) {
            printf("No data for segment at %p\n", (void*)p->segments[i].phdr.p_vaddr);
            continue;
        }


        if(write(fd, p->segments[i].segment, p->segments[i].phdr.p_filesz) != p->segments[i].phdr.p_filesz)
            return 0;

        p->segments[i].phdr.p_offset = off;
        off += p->segments[i].phdr.p_filesz;
        off = PAGE_ALIGN(off);

        if(lseek(fd, off, SEEK_SET) < 0) 
            return 0;

        printf("Done.\n");
    }

    if(lseek(fd, p->ehdr.e_phoff, SEEK_SET) < 0)
        return 0;

    for (i=0; i < p->ehdr.e_phnum; i++) {
        if(write(fd, &p->segments[i].phdr, sizeof(p->segments[i].phdr)) != sizeof(p->segments[i].phdr))
            return 0;
    }  
    
    /* TODO:Change entry_point */
    if(lseek(fd, 0, SEEK_SET) < 0)
        return 0;    
    
    if(write(fd, &p->ehdr, sizeof(p->ehdr)) != sizeof(p->ehdr))
       return 0;

    return 1;
}

int undump_add_elf_segment(undumped_program *p)
{
    Elf32_Phdr phdr;
    undump_segment *seg;

    phdr.p_offset = 0;
    phdr.p_filesz = phdr.p_memsz = 0x54;
    phdr.p_vaddr  = elf_get_nextvaddr(p);
    phdr.p_paddr  = 0;
    phdr.p_align  = 4096;
    phdr.p_type   = PT_LOAD;
    phdr.p_flags  = PF_R | PF_X;

    seg = elf_add_segment(p, NULL, &phdr);
    return 1;
}

int undump(const char *new_file, struct program *p, struct core *c)
{
    int fd;
    undumped_program *prog = elf_new_undumped_program();

    fd = open(new_file, O_CREAT|O_RDWR, 0700);
    if(fd < 0) {
        perror("open");
        return 0;
    }
 
    undump_copy_phs(prog, c, p);

    prog->ehdr.e_entry = undump_add_restore_seg(prog, c);

        /*core_get_status(c)->pr_reg.IP;*/

    if(!undump_write_undumped(fd, prog)) {
        perror("write");
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    struct options op;
    if (!_get_options(argc, argv, &op)) {
        fprintf(stderr, "Syntax: undump <core-file> <original-executable> <new-file-name>\n");
        return 2;
    }

    struct core *c = load_core(op.core_file_name);
    struct program *p = prog_read_elf(op.program_file_name);

    if(!c  || !p) {
        perror("??");
        return 2;
    }

    dump_core_data(c);
    dump_program_data(p);

    undump(op.new_file, p, c);
    return 0;
}
