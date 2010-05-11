#ifndef __CORE_H
#define __CORE_H


#include <elf.h>
#include <unistd.h>
#include <sys/types.h>

#define CORE_MAGIC "CORE\0\0\0\0"

#if defined(__i386__) || defined(__x86_64__)
  typedef struct i386_regs {    /* Normal (non-FPU) CPU registers            */
  #ifdef __x86_64__
    #define BP rbp
    #define SP rsp
    #define IP rip
    uint64_t  r15,r14,r13,r12,rbp,rbx,r11,r10;
    uint64_t  r9,r8,rax,rcx,rdx,rsi,rdi,orig_rax;
    uint64_t  rip,cs,eflags;
    uint64_t  rsp,ss;
    uint64_t  fs_base, gs_base;
    uint64_t  ds,es,fs,gs;
  #else
    #define BP ebp
    #define SP esp
    #define IP eip
    uint32_t  ebx, ecx, edx, esi, edi, ebp, eax;
    uint16_t  ds, __ds, es, __es;
    uint16_t  fs, __fs, gs, __gs;
    uint32_t  orig_eax, eip;
    uint16_t  cs, __cs;
    uint32_t  eflags, esp;
    uint16_t  ss, __ss;
  #endif
  } i386_regs;
  #define regs i386_regs
#elif defined(__ARM_ARCH_3__)
  typedef struct arm_regs {     /* General purpose registers                 */
    #define BP uregs[11]        /* Frame pointer                             */
    #define SP uregs[13]        /* Stack pointer                             */
    #define IP uregs[15]        /* Program counter                           */
    #define LR uregs[14]        /* Link register                             */
    long uregs[18];
  } arm_regs;
  #define regs arm_regs
#elif defined(__mips__)
  typedef struct mips_regs {
    unsigned long pad[6];       /* Unused padding to match kernel structures */
    unsigned long uregs[32];    /* General purpose registers.                */
    unsigned long hi;           /* Used for multiplication and division.     */
    unsigned long lo;
    unsigned long cp0_epc;      /* Program counter.                          */
    unsigned long cp0_badvaddr;
    unsigned long cp0_status;
    unsigned long cp0_cause;
    unsigned long unused;
  } mips_regs;
  #define regs mips_regs
#endif

/* Data structures found in x86-32/64, ARM, and MIPS core dumps on Linux;
 * similar data structures are defined in /usr/include/{linux,asm}/... but
 * those headers conflict with the rest of the libc headers. So we cannot
 * include them here.
 */

#if defined(__i386__) || defined(__x86_64__)
  #if !defined(__x86_64__)
    typedef struct fpregs {     /* FPU registers                             */
      uint32_t  cwd;
      uint32_t  swd;
      uint32_t  twd;
      uint32_t  fip;
      uint32_t  fcs;
      uint32_t  foo;
      uint32_t  fos;
      uint32_t  st_space[20];   /* 8*10 bytes for each FP-reg = 80 bytes     */
    } fpregs;
    typedef struct fpxregs {    /* SSE registers                             */
    #define FPREGS fpxregs
  #else
    typedef struct fpxregs {    /* x86-64 stores FPU registers in SSE struct */
    } fpxregs;
    typedef struct fpregs {     /* FPU registers                             */
    #define FPREGS fpregs
  #endif
    uint16_t  cwd;
    uint16_t  swd;
    uint16_t  twd;
    uint16_t  fop;
    uint32_t  fip;
    uint32_t  fcs;
    uint32_t  foo;
    uint32_t  fos;
    uint32_t  mxcsr;
    uint32_t  mxcsr_mask;
    uint32_t  st_space[32];     /*  8*16 bytes for each FP-reg  = 128 bytes  */
    uint32_t  xmm_space[64];    /* 16*16 bytes for each XMM-reg = 128 bytes  */
    uint32_t  padding[24];
  } FPREGS;
  #undef FPREGS
  #define regs i386_regs        /* General purpose registers                 */
#elif defined(__ARM_ARCH_3__)
  typedef struct fpxregs {      /* No extended FPU registers on ARM          */
  } fpxregs;
  typedef struct fpregs {       /* FPU registers                             */
    struct fp_reg {
      unsigned int sign1:1;
      unsigned int unused:15;
      unsigned int sign2:1;
      unsigned int exponent:14;
      unsigned int j:1;
      unsigned int mantissa1:31;
      unsigned int mantissa0:32;
    } fpregs[8];
    unsigned int   fpsr:32;
    unsigned int   fpcr:32;
    unsigned char  ftype[8];
    unsigned int   init_flag;
  } fpregs;
  #define regs arm_regs         /* General purpose registers                 */
#elif defined(__mips__)
  typedef struct fpxregs {      /* No extended FPU registers on MIPS         */
  } fpxregs;
  typedef struct fpregs {
    uint64_t fpuregs[32];
    uint32_t fcr31;
    uint32_t fir;
  } fpregs;
  #define regs mips_regs
#endif

typedef struct elf_timeval {    /* Time value with microsecond resolution    */
  long tv_sec;                  /* Seconds                                   */
  long tv_usec;                 /* Microseconds                              */
} elf_timeval;


typedef struct elf_siginfo {    /* Information about signal (unused)         */
  int32_t si_signo;             /* Signal number                             */
  int32_t si_code;              /* Extra code                                */
  int32_t si_errno;             /* Errno                                     */
} elf_siginfo;

typedef struct prstatus {       /* Information about thread; includes CPU reg*/
    elf_siginfo    pr_info;       /* Info associated with signal               */
    uint16_t       pr_cursig;     /* Current signal                            */
    unsigned long  pr_sigpend;    /* Set of pending signals                    */
    unsigned long  pr_sighold;    /* Set of held signals                       */
    pid_t          pr_pid;        /* Process ID                                */
    pid_t          pr_ppid;       /* Parent's process ID                       */
    pid_t          pr_pgrp;       /* Group ID                                  */
    pid_t          pr_sid;        /* Session ID                                */
    elf_timeval    pr_utime;      /* User time                                 */
    elf_timeval    pr_stime;      /* System time                               */
    elf_timeval    pr_cutime;     /* Cumulative user time                      */
    elf_timeval    pr_cstime;     /* Cumulative system time                    */
    regs           pr_reg;        /* CPU registers                             */
    uint32_t       pr_fpvalid;    /* True if math co-processor being used      */
} prstatus;

struct core {
    char *core;   /* A pointer to the content of the file */
    Elf32_Ehdr *header;
    prstatus *status;
    int fd;
    off_t size;
};

struct core *load_core(char *filename);
int core_parse_core(struct core *c, char *data);
Elf32_Phdr *core_get_program_headers(struct core *c);
prstatus *core_get_status(struct core *c);
void dump_core_data(struct core *c);

#endif
