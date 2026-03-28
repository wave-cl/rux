.global _start
_start:
    mov x8, #64
    mov x0, #1
    adr x1, msg
    mov x2, #msg_end - msg
    svc #0
    mov x8, #93
    mov x0, #0
    svc #0
msg:    .ascii "rux 0.1.0 aarch64\n"
msg_end:
