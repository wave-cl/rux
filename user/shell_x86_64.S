.global _start
_start:
    mov $2, %r12            # loop counter: run 2 commands

shell_loop:
    # write(1, "rux$ ", 5)
    mov $1, %rax
    mov $1, %rdi
    lea prompt(%rip), %rsi
    mov $5, %rdx
    int $0x80

    # vfork()
    mov $57, %rax
    int $0x80

    test %rax, %rax
    jz child

parent:
    # wait(child_pid)
    mov %rax, %rdi
    mov $61, %rax
    xor %rsi, %rsi
    xor %rdx, %rdx
    int $0x80

    # write(1, "done\n", 5)
    mov $1, %rax
    mov $1, %rdi
    lea done_msg(%rip), %rsi
    mov $5, %rdx
    int $0x80

    dec %r12
    jnz shell_loop

    # exit(0)
    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

child:
    # exec("/hello")
    mov $59, %rax
    lea hello_path(%rip), %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    int $0x80

    # exec failed — exit(1)
    mov $60, %rax
    mov $1, %rdi
    int $0x80

prompt:     .ascii "rux$ "
done_msg:   .ascii "done\n"
hello_path: .asciz "/hello"
