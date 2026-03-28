.global _start
_start:
    # ── Run /hello ──────────────────────────────────
    lea hello_path(%rip), %r12
    call run_command

    # ── Run /count ──────────────────────────────────
    lea count_path(%rip), %r12
    call run_command

    # exit(0)
    mov $60, %rax
    xor %rdi, %rdi
    int $0x80

# Subroutine: print prompt, vfork, child execs *%r12, parent waits
run_command:
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
    jz .child

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

    ret

.child:
    # exec(r12)
    mov $59, %rax
    mov %r12, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    int $0x80

    # exec failed
    mov $60, %rax
    mov $1, %rdi
    int $0x80

prompt:      .ascii "rux$ "
done_msg:    .ascii "done\n"
hello_path:  .asciz "/hello"
count_path:  .asciz "/count"
