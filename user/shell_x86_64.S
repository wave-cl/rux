.global _start
_start:
    # write(1, "rux$ ", 5)
    mov $1, %rax
    mov $1, %rdi
    lea prompt(%rip), %rsi
    mov $5, %rdx
    int $0x80

    # fork()
    mov $57, %rax
    int $0x80
    # RAX = child PID (parent) or 0 (child)

    test %rax, %rax
    jz child

parent:
    # wait(child_pid, NULL, 0)
    mov %rax, %rdi        # pid = child PID
    mov $61, %rax         # syscall: wait
    xor %rsi, %rsi        # wstatus = NULL
    xor %rdx, %rdx        # options = 0
    int $0x80

    # write(1, "rux$ done\n", 10)
    mov $1, %rax
    mov $1, %rdi
    lea done_msg(%rip), %rsi
    mov $10, %rdx
    int $0x80

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
done_msg:   .ascii "rux$ done\n"
hello_path: .asciz "/hello"
