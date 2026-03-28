.global _start
_start:
    # Get ticks (1000 Hz)
    mov $96, %rax
    int $0x80
    mov %rax, %r12              # save ticks

    # Divide by 1000 → seconds
    xor %rdx, %rdx
    mov $1000, %rcx
    div %rcx
    mov %rax, %r13              # seconds

    # Convert seconds to decimal string (right to left in numbuf)
    lea numbuf+18(%rip), %rdi
    movb $0, (%rdi)             # null terminator
    mov %r13, %rax
    test %rax, %rax
    jnz .cvt
    dec %rdi
    movb $'0', (%rdi)
    jmp .print
.cvt:
    test %rax, %rax
    jz .print
    dec %rdi
    xor %rdx, %rdx
    mov $10, %rcx
    div %rcx
    add $'0', %dl
    mov %dl, (%rdi)
    jmp .cvt

.print:
    # rdi = start of number string
    mov %rdi, %r14              # save start

    # "up "
    mov $1, %rax
    mov $1, %rdi
    lea prefix(%rip), %rsi
    mov $3, %rdx
    int $0x80

    # number
    mov $1, %rax
    mov $1, %rdi
    mov %r14, %rsi
    lea numbuf+18(%rip), %rdx
    sub %r14, %rdx              # length of number string
    int $0x80

    # "s\n"
    mov $1, %rax
    mov $1, %rdi
    lea suffix(%rip), %rsi
    mov $2, %rdx
    int $0x80

    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

.data
prefix:  .ascii "up "
suffix:  .ascii "s\n"

.bss
numbuf:  .space 20
