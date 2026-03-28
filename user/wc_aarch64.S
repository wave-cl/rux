.global _start
_start:
    ldr x0, [sp, #0]
    cmp x0, #2
    b.lt usage

    ldr x5, [sp, #16]
    adr x6, pathbuf
    add x6, x6, #1
.cp:
    ldrb w4, [x5]
    strb w4, [x6]
    cbz w4, .open
    add x5, x5, #1
    add x6, x6, #1
    b .cp

.open:
    mov x8, #56                 // open
    adr x0, pathbuf
    svc #0
    cmp x0, #0
    b.lt err
    mov x19, x0                 // fd
    mov x20, #0                 // bytes
    mov x21, #0                 // lines
    mov x22, #0                 // words
    mov x23, #0                 // in_word

.read:
    mov x8, #63
    mov x0, x19
    adr x1, filebuf
    mov x2, #4096
    svc #0
    cmp x0, #0
    b.le .done
    add x20, x20, x0           // total bytes
    mov x24, x0                 // bytes_read
    adr x25, filebuf
    mov x26, #0                 // index
.scan:
    cmp x26, x24
    b.eq .read
    ldrb w4, [x25, x26]
    cmp w4, #0x0A
    b.eq .newline
    cmp w4, #' '
    b.eq .space
    cmp w4, #0x09
    b.eq .space
    // printable
    cbnz x23, .next
    mov x23, #1
    add x22, x22, #1
    b .next
.newline:
    add x21, x21, #1
.space:
    mov x23, #0
.next:
    add x26, x26, #1
    b .scan

.done:
    mov x8, #57
    mov x0, x19
    svc #0

    // Print lines words bytes filename
    mov x0, x21
    bl print_num
    bl print_space
    mov x0, x22
    bl print_num
    bl print_space
    mov x0, x20
    bl print_num
    bl print_space

    // Print filename
    ldr x5, [sp, #16]
    mov x6, x5
    mov x2, #0
.flen:
    ldrb w4, [x6, x2]
    cbz w4, .fprint
    add x2, x2, #1
    b .flen
.fprint:
    mov x8, #64
    mov x0, #1
    mov x1, x5
    svc #0

    mov x8, #64
    mov x0, #1
    adr x1, nl
    mov x2, #1
    svc #0

    mov x8, #93
    mov x0, #0
    svc #0

print_space:
    stp x29, x30, [sp, #-16]!
    mov x8, #64
    mov x0, #1
    adr x1, space
    mov x2, #1
    svc #0
    ldp x29, x30, [sp], #16
    ret

// print_num: print x0 as decimal
print_num:
    stp x29, x30, [sp, #-16]!
    adr x5, numbuf
    add x5, x5, #18
    mov w4, #0
    strb w4, [x5]
    cbz x0, .pn_zero
    b .pn_check
.pn_zero:
    sub x5, x5, #1
    mov w4, #'0'
    strb w4, [x5]
    b .pn_print
.pn_check:
    cbz x0, .pn_print
.pn_cvt:
    sub x5, x5, #1
    mov x1, #10
    udiv x2, x0, x1
    msub x3, x2, x1, x0
    add w3, w3, #'0'
    strb w3, [x5]
    mov x0, x2
    cbnz x0, .pn_cvt
.pn_print:
    adr x3, numbuf
    add x3, x3, #18
    sub x2, x3, x5
    mov x8, #64
    mov x0, #1
    mov x1, x5
    svc #0
    ldp x29, x30, [sp], #16
    ret

err:
    mov x8, #64
    mov x0, #1
    adr x1, err_msg
    mov x2, #10
    svc #0
    mov x8, #93
    mov x0, #1
    svc #0

usage:
    mov x8, #64
    mov x0, #1
    adr x1, usage_msg
    mov x2, #uend - usage_msg
    svc #0
    mov x8, #93
    mov x0, #1
    svc #0

.data
space:      .ascii " "
nl:         .ascii "\n"
err_msg:    .ascii "not found\n"
usage_msg:  .ascii "usage: wc <name>\n"
uend:
pathbuf:    .byte '/'
            .space 31, 0

.bss
numbuf:     .space 20
filebuf:    .space 4096
