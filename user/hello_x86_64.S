.global _start
_start:
    # write(1, msg, 14)
    mov $1, %rax        # syscall: write
    mov $1, %rdi        # fd: stdout
    lea msg(%rip), %rsi # buf
    mov $14, %rdx       # len
    int $0x80

    # exit(0)
    mov $60, %rax       # syscall: exit
    xor %rdi, %rdi      # status: 0
    int $0x80

msg:
    .ascii "Hello, world!\n"
