.global _start
_start:

shell_loop:
    # write(1, "rux$ ", 5)
    mov $1, %rax
    mov $1, %rdi
    lea prompt(%rip), %rsi
    mov $5, %rdx
    int $0x80

    # Read line into linebuf
    lea linebuf(%rip), %r12     # write pointer
    xor %r13, %r13              # length
read_loop:
    mov $0, %rax
    mov $0, %rdi
    lea tmpbyte(%rip), %rsi
    mov $1, %rdx
    int $0x80
    movzbl tmpbyte(%rip), %eax
    cmp $0x0A, %al
    je read_done
    cmp $0x0D, %al
    je read_done
    # echo
    push %rax
    mov $1, %rax
    mov $1, %rdi
    lea tmpbyte(%rip), %rsi
    mov $1, %rdx
    int $0x80
    pop %rax
    cmp $62, %r13               # max 62 chars
    jge read_loop
    mov %al, (%r12)
    inc %r12
    inc %r13
    jmp read_loop

read_done:
    movb $0, (%r12)             # null-terminate
    # echo newline
    mov $1, %rax
    mov $1, %rdi
    lea newline(%rip), %rsi
    mov $1, %rdx
    int $0x80

    # If empty, loop
    test %r13, %r13
    jz shell_loop

    # If "q", exit
    cmpb $'q', linebuf(%rip)
    jne parse_cmd
    cmp $1, %r13
    je shell_exit

parse_cmd:
    # Split linebuf at first space into cmdbuf (path) and argbuf (arg)
    # cmdbuf = "/" + cmd, argbuf = rest after space
    lea linebuf(%rip), %rsi     # source
    lea cmdbuf+1(%rip), %rdi    # dest (skip leading '/')
    xor %rcx, %rcx              # cmd length
copy_cmd:
    movzbl (%rsi), %eax
    test %al, %al
    jz cmd_done
    cmp $' ', %al
    je found_space
    mov %al, (%rdi)
    inc %rsi
    inc %rdi
    inc %rcx
    jmp copy_cmd

found_space:
    movb $0, (%rdi)             # null-terminate cmd
    inc %rsi                    # skip space
    # Copy rest to argbuf
    lea argbuf(%rip), %rdi
copy_arg:
    movzbl (%rsi), %eax
    mov %al, (%rdi)
    test %al, %al
    jz do_exec
    inc %rsi
    inc %rdi
    jmp copy_arg

cmd_done:
    movb $0, (%rdi)             # null-terminate cmd
    movb $0, argbuf(%rip)       # empty arg

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
    # exec(cmdbuf, argbuf_or_null)
    mov $59, %rax
    lea cmdbuf(%rip), %rdi      # path
    # If argbuf is empty, pass NULL
    cmpb $0, argbuf(%rip)
    je no_arg
    lea argbuf(%rip), %rsi      # arg
    jmp do_exec_syscall
no_arg:
    xor %rsi, %rsi
do_exec_syscall:
    xor %rdx, %rdx
    int $0x80

    # exec failed
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
            .space 31, 0
argbuf:     .space 32, 0
tmpbyte:    .byte 0
linebuf:    .space 64, 0
