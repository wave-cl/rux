.global _start
_start:
    // Get ticks (1000 Hz)
    mov x8, #169
    svc #0
    mov x19, x0                // save ticks

    // Divide by 1000 → seconds
    mov x1, #1000
    udiv x20, x19, x1          // x20 = seconds

    // Convert to decimal (right to left in numbuf)
    adr x5, numbuf
    add x5, x5, #18
    mov w4, #0
    strb w4, [x5]              // null terminator
    mov x0, x20
    cbz x0, .zero
    b .cvt_check
.zero:
    sub x5, x5, #1
    mov w4, #'0'
    strb w4, [x5]
    b .print
.cvt_check:
    cbz x0, .print
.cvt:
    sub x5, x5, #1
    mov x1, #10
    udiv x2, x0, x1
    msub x3, x2, x1, x0       // x3 = x0 % 10
    add w3, w3, #'0'
    strb w3, [x5]
    mov x0, x2
    cbnz x0, .cvt

.print:
    mov x21, x5                // save start of number

    // "up "
    mov x8, #64
    mov x0, #1
    adr x1, prefix
    mov x2, #3
    svc #0

    // number
    adr x3, numbuf
    add x3, x3, #18
    sub x2, x3, x21            // length
    mov x8, #64
    mov x0, #1
    mov x1, x21
    svc #0

    // "s\n"
    mov x8, #64
    mov x0, #1
    adr x1, suffix
    mov x2, #2
    svc #0

    mov x8, #93
    mov x0, #0
    svc #0

.data
prefix:  .ascii "up "
suffix:  .ascii "s\n"

.bss
numbuf:  .space 20
