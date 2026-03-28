.global _start
_start:
    # Check argv[1] = filename
    mov (%rsp), %rax
    cmp $2, %rax
    jl usage

    # Build path: "/" + argv[1]
    mov 16(%rsp), %rsi
    lea pathbuf+1(%rip), %rdi
.cp:
    movzbl (%rsi), %eax
    mov %al, (%rdi)
    test %al, %al
    jz .cp_done
    inc %rsi
    inc %rdi
    jmp .cp
.cp_done:

    # creat(pathbuf)
    mov $8, %rax
    lea pathbuf(%rip), %rdi
    int $0x80
    cmp $0, %rax
    jl err_creat
    mov %rax, %r12              # fd

    # Print "content: "
    mov $1, %rax
    mov $1, %rdi
    lea prompt(%rip), %rsi
    mov $9, %rdx
    int $0x80

    # Read content from stdin until newline
    lea contentbuf(%rip), %r13
    xor %r14, %r14
.rd:
    mov $0, %rax
    mov $0, %rdi
    lea tmpbyte(%rip), %rsi
    mov $1, %rdx
    int $0x80
    movzbl tmpbyte(%rip), %eax
    cmp $0x0A, %al
    je .rd_done
    cmp $0x0D, %al
    je .rd_done
    # echo
    push %rax
    mov $1, %rax
    mov $1, %rdi
    lea tmpbyte(%rip), %rsi
    mov $1, %rdx
    int $0x80
    pop %rax
    cmp $255, %r14
    jge .rd
    mov %al, (%r13,%r14)
    inc %r14
    jmp .rd

.rd_done:
    # Add newline to content
    movb $0x0A, (%r13,%r14)
    inc %r14

    # Echo newline
    mov $1, %rax
    mov $1, %rdi
    lea nl(%rip), %rsi
    mov $1, %rdx
    int $0x80

    # write(fd, contentbuf, len)
    mov $1, %rax
    mov %r12, %rdi
    lea contentbuf(%rip), %rsi
    mov %r14, %rdx
    int $0x80

    # close(fd)
    mov $3, %rax
    mov %r12, %rdi
    int $0x80

    # Print "ok\n"
    mov $1, %rax
    mov $1, %rdi
    lea ok_msg(%rip), %rsi
    mov $3, %rdx
    int $0x80

    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

err_creat:
    mov $1, %rax
    mov $1, %rdi
    lea err_msg(%rip), %rsi
    mov $6, %rdx
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
prompt:     .ascii "content: "
nl:         .ascii "\n"
ok_msg:     .ascii "ok\n"
err_msg:    .ascii "error\n"
usage_msg:  .ascii "usage: mkfile <name>\n"
uend:
pathbuf:    .byte '/'
            .space 31, 0
tmpbyte:    .byte 0

.bss
contentbuf: .space 256
