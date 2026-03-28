.global _start
_start:
    # Print "file: "
    mov $1, %rax
    mov $1, %rdi
    lea file_prompt(%rip), %rsi
    mov $6, %rdx
    int $0x80

    # Read filename (up to newline)
    lea pathbuf+1(%rip), %r12    # skip leading '/'
    xor %r13, %r13
read_name:
    mov $0, %rax
    mov $0, %rdi
    lea tmpbyte(%rip), %rsi
    mov $1, %rdx
    int $0x80
    movzbl tmpbyte(%rip), %eax
    cmp $0x0A, %al
    je name_done
    cmp $0x0D, %al
    je name_done
    # echo
    push %rax
    mov $1, %rax
    mov $1, %rdi
    lea tmpbyte(%rip), %rsi
    mov $1, %rdx
    int $0x80
    pop %rax
    cmp $15, %r13
    jge read_name
    mov %al, (%r12)
    inc %r12
    inc %r13
    jmp read_name

name_done:
    movb $0, (%r12)             # null-terminate
    # echo newline
    mov $1, %rax
    mov $1, %rdi
    lea newline(%rip), %rsi
    mov $1, %rdx
    int $0x80

    # open(pathbuf)
    mov $2, %rax
    lea pathbuf(%rip), %rdi
    int $0x80
    cmp $0, %rax
    jl err_open
    mov %rax, %r14              # save fd

    # read loop
read_file:
    mov $0, %rax
    mov %r14, %rdi
    lea filebuf(%rip), %rsi
    mov $4096, %rdx
    int $0x80
    cmp $0, %rax
    jle done_read

    # write what we read
    mov %rax, %rdx              # len
    mov $1, %rax
    mov $1, %rdi
    lea filebuf(%rip), %rsi
    int $0x80
    jmp read_file

done_read:
    # close(fd)
    mov $3, %rax
    mov %r14, %rdi
    int $0x80

    # exit(0)
    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

err_open:
    mov $1, %rax
    mov $1, %rdi
    lea err_msg(%rip), %rsi
    mov $10, %rdx
    int $0x80
    mov $60, %rax
    mov $1, %rdi
    int $0x80

.data
file_prompt: .ascii "file: "
newline:     .ascii "\n"
err_msg:     .ascii "not found\n"
pathbuf:     .byte '/'
             .space 16, 0
tmpbyte:     .byte 0

.bss
filebuf:     .space 4096
