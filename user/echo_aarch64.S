.global _start
_start:
    // argv: [sp]=argc, [sp+8]=argv[0], [sp+16]=argv[1]
    ldr x0, [sp, #0]
    cmp x0, #2
    b.lt usage

    // Write argv[1] to stdout
    ldr x5, [sp, #16]          // message pointer
    // Find length
    mov x6, x5
    mov x2, #0
.len:
    ldrb w4, [x6, x2]
    cbz w4, .write_msg
    add x2, x2, #1
    b .len
.write_msg:
    mov x8, #64
    mov x0, #1
    mov x1, x5
    // x2 = length
    svc #0

    // newline
    mov x8, #64
    mov x0, #1
    adr x1, newline
    mov x2, #1
    svc #0

    mov x8, #93
    mov x0, #0
    svc #0

usage:
    mov x8, #64
    mov x0, #1
    adr x1, usage_msg
    mov x2, #usage_end - usage_msg
    svc #0
    mov x8, #93
    mov x0, #1
    svc #0

newline:    .ascii "\n"
usage_msg:  .ascii "usage: echo <text>\n"
usage_end:
