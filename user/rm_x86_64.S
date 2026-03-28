.global _start
_start:
    mov (%rsp), %rax
    cmp $2, %rax
    jl usage

    # Build "/" + argv[1]
    mov 16(%rsp), %rsi
    lea pathbuf+1(%rip), %rdi
.cp:
    movzbl (%rsi), %eax
    mov %al, (%rdi)
    test %al, %al
    jz .do_rm
    inc %rsi
    inc %rdi
    jmp .cp

.do_rm:
    mov $87, %rax               # unlink
    lea pathbuf(%rip), %rdi
    int $0x80
    test %rax, %rax
    jnz err
    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

err:
    mov $1, %rax
    mov $1, %rdi
    lea err_msg(%rip), %rsi
    mov $10, %rdx
    int $0x80
    mov $60, %rax
    mov $1, %rdi
    int $0x80

usage:
    mov $1, %rax
    mov $1, %rdi
    lea usage_msg(%rip), %rsi
    mov $uend - usage_msg, %rdx
    int $0x80
    mov $60, %rax
    mov $1, %rdi
    int $0x80

.data
err_msg:    .ascii "not found\n"
usage_msg:  .ascii "usage: rm <name>\n"
uend:
pathbuf:    .byte '/'
            .space 31, 0
