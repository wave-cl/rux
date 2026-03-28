.global _start
_start:
    # ── Command 1: /hello ───────────────────────────
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
    jz child1

    # parent: wait
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

    # ── Command 2: /count ───────────────────────────
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
    jz child2

    # parent: wait
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

    # exit(0)
    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

child1:
    mov $59, %rax
    lea hello_path(%rip), %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    int $0x80
    # unreachable
    mov $60, %rax
    mov $1, %rdi
    int $0x80

child2:
    mov $59, %rax
    lea count_path(%rip), %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    int $0x80
    # unreachable
    mov $60, %rax
    mov $1, %rdi
    int $0x80

prompt:      .ascii "rux$ "
done_msg:    .ascii "done\n"
hello_path:  .asciz "/hello"
count_path:  .asciz "/count"
