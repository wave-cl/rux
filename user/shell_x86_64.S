.global _start
_start:

shell_loop:
    # write(1, "rux$ ", 5)
    mov $1, %rax
    mov $1, %rdi
    lea prompt(%rip), %rsi
    mov $5, %rdx
    int $0x80

    # Read command into cmdbuf: read one byte at a time until '\n' or '\r'
    lea cmdbuf+1(%rip), %r12    # write pointer (skip leading '/')
    xor %r13, %r13              # length counter
read_loop:
    # read(0, byte, 1)
    mov $0, %rax
    mov $0, %rdi
    lea tmpbyte(%rip), %rsi
    mov $1, %rdx
    int $0x80

    # Load the byte
    movzbl tmpbyte(%rip), %eax

    # Check for newline/carriage return
    cmp $0x0A, %al
    je read_done
    cmp $0x0D, %al
    je read_done

    # Echo the character
    push %rax
    mov $1, %rax
    mov $1, %rdi
    lea tmpbyte(%rip), %rsi
    mov $1, %rdx
    int $0x80
    pop %rax

    # Store in buffer (max 15 chars for command name)
    cmp $15, %r13
    jge read_loop
    mov %al, (%r12)
    inc %r12
    inc %r13
    jmp read_loop

read_done:
    # Echo newline
    mov $1, %rax
    mov $1, %rdi
    lea newline(%rip), %rsi
    mov $1, %rdx
    int $0x80

    # Null-terminate the path: cmdbuf = "/" + name + '\0'
    movb $0, (%r12)

    # If empty command, loop
    test %r13, %r13
    jz shell_loop

    # If "q", exit
    cmpb $'q', cmdbuf+1(%rip)
    jne do_exec
    cmp $1, %r13
    je shell_exit

do_exec:
    # vfork()
    mov $57, %rax
    int $0x80
    test %rax, %rax
    jz child

    # parent: wait
    mov %rax, %rdi
    mov $61, %rax
    xor %rsi, %rsi
    xor %rdx, %rdx
    int $0x80

    jmp shell_loop

child:
    # exec(cmdbuf)  — cmdbuf starts with '/' + name + '\0'
    mov $59, %rax
    lea cmdbuf(%rip), %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    int $0x80

    # exec failed — print error and exit
    mov $1, %rax
    mov $1, %rdi
    lea err_msg(%rip), %rsi
    mov $10, %rdx
    int $0x80

    mov $60, %rax
    mov $1, %rdi
    int $0x80

shell_exit:
    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

.data
prompt:     .ascii "rux$ "
newline:    .ascii "\n"
err_msg:    .ascii "not found\n"
cmdbuf:     .byte '/'           # leading slash
            .space 16, 0        # room for name + null
tmpbyte:    .byte 0
