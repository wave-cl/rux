.global _start
_start:
    # write(1, "rux$ ", 5)
    mov $1, %rax        # syscall: write
    mov $1, %rdi        # fd: stdout
    lea prompt(%rip), %rsi # buf
    mov $5, %rdx        # len
    int $0x80

    # exec("/hello", NULL, NULL)
    mov $59, %rax       # syscall: exec
    lea path(%rip), %rdi # path
    xor %rsi, %rsi      # argv = NULL
    xor %rdx, %rdx      # envp = NULL
    int $0x80

    # If exec returns (error), exit(1)
    mov $60, %rax
    mov $1, %rdi
    int $0x80

prompt: .ascii "rux$ "
path: .asciz "/hello"
