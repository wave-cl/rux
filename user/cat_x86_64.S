.global _start
_start:
    # Check argc: [rsp+0] = argc, [rsp+16] = argv[1]
    mov (%rsp), %rax            # argc
    cmp $2, %rax
    jl prompt_mode

    # argv[1] is the filename — construct "/filename" in pathbuf
    mov 16(%rsp), %rsi          # argv[1] pointer
    lea pathbuf+1(%rip), %rdi   # skip leading '/'
copy_argv:
    movzbl (%rsi), %eax
    mov %al, (%rdi)
    test %al, %al
    jz open_file
    inc %rsi
    inc %rdi
    jmp copy_argv

prompt_mode:
    # No argument — prompt for filename
    mov $1, %rax
    mov $1, %rdi
    lea file_prompt(%rip), %rsi
    mov $6, %rdx
    int $0x80

    lea pathbuf+1(%rip), %r12
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
    movb $0, (%r12)
    mov $1, %rax
    mov $1, %rdi
    lea newline(%rip), %rsi
    mov $1, %rdx
    int $0x80

open_file:
    # open(pathbuf)
    mov $2, %rax
    lea pathbuf(%rip), %rdi
    int $0x80
    cmp $0, %rax
    jl err_open
    mov %rax, %r14

read_file:
    mov $0, %rax
    mov %r14, %rdi
    lea filebuf(%rip), %rsi
    mov $4096, %rdx
    int $0x80
    cmp $0, %rax
    jle done_read
    mov %rax, %rdx
    mov $1, %rax
    mov $1, %rdi
    lea filebuf(%rip), %rsi
    int $0x80
    jmp read_file

done_read:
    mov $3, %rax
    mov %r14, %rdi
    int $0x80
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
             .space 31, 0
tmpbyte:     .byte 0

.bss
filebuf:     .space 4096
