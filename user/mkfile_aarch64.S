.global _start
_start:
    ldr x0, [sp, #0]
    cmp x0, #2
    b.lt usage

    // Build path: "/" + argv[1]
    ldr x5, [sp, #16]
    adr x6, pathbuf
    add x6, x6, #1
.cp:
    ldrb w4, [x5]
    strb w4, [x6]
    cbz w4, .cp_done
    add x5, x5, #1
    add x6, x6, #1
    b .cp
.cp_done:

    // creat(pathbuf) — syscall 35
    mov x8, #35
    adr x0, pathbuf
    svc #0
    cmp x0, #0
    b.lt err_creat
    mov x19, x0                 // fd

    // Print "content: "
    mov x8, #64
    mov x0, #1
    adr x1, prompt
    mov x2, #9
    svc #0

    // Read content from stdin until newline
    adr x20, contentbuf
    mov x21, #0                 // length
.rd:
    mov x8, #63
    mov x0, #0
    adr x1, tmpbyte
    mov x2, #1
    svc #0
    adr x3, tmpbyte
    ldrb w4, [x3]
    cmp w4, #0x0A
    b.eq .rd_done
    cmp w4, #0x0D
    b.eq .rd_done
    // echo
    mov x8, #64
    mov x0, #1
    adr x1, tmpbyte
    mov x2, #1
    svc #0
    cmp x21, #255
    b.ge .rd
    strb w4, [x20, x21]
    add x21, x21, #1
    b .rd

.rd_done:
    // Add newline
    mov w4, #0x0A
    strb w4, [x20, x21]
    add x21, x21, #1

    // Echo newline
    mov x8, #64
    mov x0, #1
    adr x1, nl
    mov x2, #1
    svc #0

    // write(fd, contentbuf, len)
    mov x8, #64
    mov x0, x19
    adr x1, contentbuf
    mov x2, x21
    svc #0

    // close(fd)
    mov x8, #57
    mov x0, x19
    svc #0

    // Print "ok\n"
    mov x8, #64
    mov x0, #1
    adr x1, ok_msg
    mov x2, #3
    svc #0

    mov x8, #93
    mov x0, #0
    svc #0

err_creat:
    mov x8, #64
    mov x0, #1
    adr x1, err_msg
    mov x2, #6
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
prompt:     .ascii "content: "
nl:         .ascii "\n"
ok_msg:     .ascii "ok\n"
err_msg:    .ascii "error\n"
usage_msg:  .ascii "usage: mkfile <name>\n"
uend:
pathbuf:    .byte '/'
            .space 31, 0
tmpbyte:    .byte 0

.bss
contentbuf: .space 256
