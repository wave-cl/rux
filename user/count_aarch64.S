.global _start
_start:
    // Print "1\n2\n3\n"
    mov x8, #64
    mov x0, #1
    adr x1, msg
    mov x2, #6
    svc #0

    // exit(0)
    mov x8, #93
    mov x0, #0
    svc #0

msg:
    .ascii "1\n2\n3\n"
