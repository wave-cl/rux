.global _start
_start:
    # Print "1\n2\n3\n"
    mov $1, %rax
    mov $1, %rdi
    lea msg(%rip), %rsi
    mov $6, %rdx
    int $0x80

    # exit(0)
    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

msg:
    .ascii "1\n2\n3\n"
