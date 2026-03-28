.global _start
_start:
    // write(1, msg, 14)
    mov x8, #64         // syscall: write (aarch64 Linux)
    mov x0, #1          // fd: stdout
    adr x1, msg         // buf
    mov x2, #14         // len
    svc #0

    // exit(0)
    mov x8, #93         // syscall: exit (aarch64 Linux)
    mov x0, #0          // status: 0
    svc #0

msg:
    .ascii "Hello, world!\n"
