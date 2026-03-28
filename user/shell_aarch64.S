.global _start
_start:

shell_loop:
    // write(1, "rux$ ", 5)
    mov x8, #64
    mov x0, #1
    adr x1, prompt
    mov x2, #5
    svc #0

    // Read command into cmdbuf: one byte at a time until '\n' or '\r'
    adr x19, cmdbuf
    add x19, x19, #1           // skip leading '/'
    mov x20, #0                // length counter

read_loop:
    // read(0, tmpbyte, 1)
    mov x8, #63
    mov x0, #0
    adr x1, tmpbyte
    mov x2, #1
    svc #0

    // Load byte
    adr x3, tmpbyte
    ldrb w4, [x3]

    // Check newline/carriage return
    cmp w4, #0x0A
    b.eq read_done
    cmp w4, #0x0D
    b.eq read_done

    // Echo the character
    mov x8, #64
    mov x0, #1
    adr x1, tmpbyte
    mov x2, #1
    svc #0

    // Store in buffer (max 15 chars)
    cmp x20, #15
    b.ge read_loop
    strb w4, [x19]
    add x19, x19, #1
    add x20, x20, #1
    b read_loop

read_done:
    // Echo newline
    mov x8, #64
    mov x0, #1
    adr x1, newline
    mov x2, #1
    svc #0

    // Null-terminate
    mov w4, #0
    strb w4, [x19]

    // If empty, loop
    cbz x20, shell_loop

    // If "q", exit
    adr x3, cmdbuf
    ldrb w4, [x3, #1]
    cmp w4, #'q'
    b.ne do_exec
    cmp x20, #1
    b.eq shell_exit

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
    // exec(cmdbuf)
    mov x8, #221
    adr x0, cmdbuf
    svc #0

    // exec failed — print error
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
            .space 16, 0
tmpbyte:    .byte 0
