.global _start
_start:

shell_loop:
    // write(1, "rux$ ", 5)
    mov x8, #64
    mov x0, #1
    adr x1, prompt
    mov x2, #5
    svc #0

    // Read line into linebuf
    adr x19, linebuf
    mov x20, #0                 // length
read_loop:
    mov x8, #63
    mov x0, #0
    adr x1, tmpbyte
    mov x2, #1
    svc #0
    adr x3, tmpbyte
    ldrb w4, [x3]
    cmp w4, #0x0A
    b.eq read_done
    cmp w4, #0x0D
    b.eq read_done
    // echo
    mov x8, #64
    mov x0, #1
    adr x1, tmpbyte
    mov x2, #1
    svc #0
    cmp x20, #62
    b.ge read_loop
    strb w4, [x19, x20]
    add x20, x20, #1
    b read_loop

read_done:
    mov w4, #0
    strb w4, [x19, x20]        // null-terminate
    // echo newline
    mov x8, #64
    mov x0, #1
    adr x1, newline
    mov x2, #1
    svc #0

    // If empty, loop
    cbz x20, shell_loop

    // If "q", exit
    adr x3, linebuf
    ldrb w4, [x3]
    cmp w4, #'q'
    b.ne parse_cmd
    cmp x20, #1
    b.eq shell_exit

parse_cmd:
    // Split linebuf at first space → cmdbuf ("/"+cmd) + argbuf
    adr x5, linebuf             // src
    adr x6, cmdbuf
    add x6, x6, #1             // skip leading '/'

copy_cmd:
    ldrb w4, [x5]
    cbz w4, cmd_done
    cmp w4, #' '
    b.eq found_space
    strb w4, [x6]
    add x5, x5, #1
    add x6, x6, #1
    b copy_cmd

found_space:
    mov w4, #0
    strb w4, [x6]              // null-terminate cmd
    add x5, x5, #1             // skip space
    adr x6, argbuf
copy_arg:
    ldrb w4, [x5]
    strb w4, [x6]
    cbz w4, do_exec
    add x5, x5, #1
    add x6, x6, #1
    b copy_arg

cmd_done:
    mov w4, #0
    strb w4, [x6]              // null-terminate cmd
    adr x6, argbuf
    strb w4, [x6]              // empty arg

do_exec:
    // vfork()
    mov x8, #220
    svc #0
    cbz x0, child

    // parent: wait4
    mov x8, #260
    mov x1, #0
    mov x2, #0
    mov x3, #0
    svc #0

    b shell_loop

child:
    // exec(cmdbuf, argbuf_or_null)
    mov x8, #221
    adr x0, cmdbuf              // path
    adr x1, argbuf
    ldrb w2, [x1]
    cbnz w2, do_exec_svc
    mov x1, #0                  // NULL if empty
do_exec_svc:
    svc #0

    // exec failed
    mov x8, #64
    mov x0, #1
    adr x1, err_msg
    mov x2, #10
    svc #0
    mov x8, #93
    mov x0, #1
    svc #0

shell_exit:
    mov x8, #93
    mov x0, #0
    svc #0

.data
prompt:     .ascii "rux$ "
newline:    .ascii "\n"
err_msg:    .ascii "not found\n"
cmdbuf:     .byte '/'
            .space 31, 0
argbuf:     .space 32, 0
tmpbyte:    .byte 0
linebuf:    .space 64, 0
