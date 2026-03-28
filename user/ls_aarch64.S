.global _start
_start:
    // getdents(buf, 4096)
    mov x8, #61
    adr x0, buf
    mov x1, #4096
    svc #0

    // x0 = bytes written
    cmp x0, #0
    b.le done

    // write(1, buf, x0)
    mov x2, x0           // len
    mov x8, #64
    mov x0, #1
    adr x1, buf
    svc #0

done:
    mov x8, #93
    mov x0, #0
    svc #0

.bss
buf:    .space 4096
