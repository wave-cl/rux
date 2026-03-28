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
    cbz w4, .do_rm
    add x5, x5, #1
    add x6, x6, #1
    b .cp

.do_rm:
    mov x8, #35                 // unlinkat
    adr x0, pathbuf
    svc #0
    cbnz x0, err
    mov x8, #93
    mov x0, #0
    svc #0

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
err_msg:    .ascii "not found\n"
usage_msg:  .ascii "usage: rm <name>\n"
uend:
pathbuf:    .byte '/'
            .space 31, 0
