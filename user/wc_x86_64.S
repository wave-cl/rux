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
    jz .open
    inc %rsi
    inc %rdi
    jmp .cp

.open:
    mov $2, %rax
    lea pathbuf(%rip), %rdi
    int $0x80
    cmp $0, %rax
    jl err
    mov %rax, %r12              # fd
    xor %r13, %r13              # bytes
    xor %r14, %r14              # lines
    xor %r15, %r15              # words
    xor %ebx, %ebx              # in_word flag

.read:
    mov $0, %rax
    mov %r12, %rdi
    lea filebuf(%rip), %rsi
    mov $4096, %rdx
    int $0x80
    cmp $0, %rax
    jle .done
    mov %rax, %rcx              # bytes read
    add %rcx, %r13              # total bytes
    lea filebuf(%rip), %rsi
    xor %rdx, %rdx              # index
.scan:
    cmp %rdx, %rcx
    je .read
    movzbl (%rsi,%rdx), %eax
    cmp $0x0A, %al
    je .newline
    cmp $' ', %al
    je .space
    cmp $0x09, %al
    je .space
    # printable char
    test %ebx, %ebx
    jnz .next
    mov $1, %ebx
    inc %r15                    # new word
    jmp .next
.newline:
    inc %r14
.space:
    xor %ebx, %ebx
.next:
    inc %rdx
    jmp .scan

.done:
    mov $3, %rax
    mov %r12, %rdi
    int $0x80

    # Print: "  lines  words  bytes filename\n"
    # Convert and print lines
    mov %r14, %rax
    call print_num
    mov $1, %rax
    mov $1, %rdi
    lea space(%rip), %rsi
    mov $1, %rdx
    int $0x80

    mov %r15, %rax
    call print_num
    mov $1, %rax
    mov $1, %rdi
    lea space(%rip), %rsi
    mov $1, %rdx
    int $0x80

    mov %r13, %rax
    call print_num
    mov $1, %rax
    mov $1, %rdi
    lea space(%rip), %rsi
    mov $1, %rdx
    int $0x80

    # Print filename (argv[1])
    mov 16(%rsp), %rsi
    xor %rcx, %rcx
.flen:
    cmpb $0, (%rsi,%rcx)
    je .fprint
    inc %rcx
    jmp .flen
.fprint:
    mov %rcx, %rdx
    mov $1, %rax
    mov $1, %rdi
    int $0x80

    mov $1, %rax
    mov $1, %rdi
    lea nl(%rip), %rsi
    mov $1, %rdx
    int $0x80

    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

# print_num: print rax as decimal
print_num:
    push %rbx
    lea numbuf+18(%rip), %rdi
    movb $0, (%rdi)
    mov %rax, %rcx
    test %rcx, %rcx
    jnz .pn_cvt
    dec %rdi
    movb $'0', (%rdi)
    jmp .pn_print
.pn_cvt:
    test %rcx, %rcx
    jz .pn_print
    dec %rdi
    mov %rcx, %rax
    xor %rdx, %rdx
    mov $10, %r8
    div %r8
    add $'0', %dl
    mov %dl, (%rdi)
    mov %rax, %rcx
    jmp .pn_cvt
.pn_print:
    mov %rdi, %rsi
    lea numbuf+18(%rip), %rax
    sub %rdi, %rax
    mov %rax, %rdx
    mov $1, %rax
    mov $1, %rdi
    int $0x80
    pop %rbx
    ret

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
space:      .ascii " "
nl:         .ascii "\n"
err_msg:    .ascii "not found\n"
usage_msg:  .ascii "usage: wc <name>\n"
uend:
pathbuf:    .byte '/'
            .space 31, 0

.bss
numbuf:     .space 20
filebuf:    .space 4096
