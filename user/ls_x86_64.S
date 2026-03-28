.global _start
_start:
    # getdents(buf, 4096)
    mov $78, %rax
    lea buf(%rip), %rdi
    mov $4096, %rsi
    int $0x80

    # rax = bytes written
    test %rax, %rax
    jle done

    # write(1, buf, rax)
    mov %rax, %rdx       # len
    mov $1, %rax
    mov $1, %rdi
    lea buf(%rip), %rsi
    int $0x80

done:
    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

.bss
buf:    .space 4096
