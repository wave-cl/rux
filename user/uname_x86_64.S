.global _start
_start:
    mov $1, %rax
    mov $1, %rdi
    lea msg(%rip), %rsi
    mov $msg_end - msg, %rdx
    int $0x80
    mov $60, %rax
    xor %rdi, %rdi
    int $0x80
msg:    .ascii "rux 0.1.0 x86_64\n"
msg_end:
