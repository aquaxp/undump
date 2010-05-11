.text
.globl _undump_start
_undump_start:

    movw $0x73, %ax
    movw %ax, %ds
    movw $0x74, %ax
    movw %ax, %es
    movw $0x75, %ax
    movw %ax, %fs
    movw $0x76, %ax
    movw %ax, %gs
	movl $0x0, %ebx
	movl $0x0, %ecx
	movl $0x0, %edx
	movl $0x0, %esi
	movl $0x0, %edi
	movl $0x0, %ebp
	movl $0x0, %eax
	movl $0xbfdb4110, %esp
    popfd 
	pushl $0x8048059
	ret
