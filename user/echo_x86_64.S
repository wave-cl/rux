.global _start
_start:
    # argv: [rsp]=argc, [rsp+8]=argv[0], [rsp+16]=argv[1]
    # argv[1] = "text" (the message to write to stdout)
    mov (%rsp), %rax
    cmp $2, %rax
    jl usage

    # Write argv[1] to stdout
    mov 16(%rsp), %rsi          # message pointer
    # Find length
    mov %rsi, %rdi
    xor %rcx, %rcx
.len:
    cmpb $0, (%rdi,%rcx)
    je .write_msg
    inc %rcx
    jmp .len
.write_msg:
    mov $1, %rax
    mov $1, %rdi
    # rsi already set
    mov %rcx, %rdx
    int $0x80

    # Write newline
    mov $1, %rax
    mov $1, %rdi
    lea newline(%rip), %rsi
    mov $1, %rdx
    int $0x80

    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

usage:
    mov $1, %rax
    mov $1, %rdi
    lea usage_msg(%rip), %rsi
    mov $usage_end - usage_msg, %rdx
    int $0x80
    mov $60, %rax
    mov $1, %rdi
    int $0x80

newline:    .ascii "\n"
usage_msg:  .ascii "usage: echo <text>\n"
usage_end:
