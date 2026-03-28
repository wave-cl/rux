.global _start
_start:
    // Print "file: "
    mov x8, #64
    mov x0, #1
    adr x1, file_prompt
    mov x2, #6
    svc #0

    // Read filename (up to newline)
    adr x19, pathbuf
    add x19, x19, #1           // skip leading '/'
    mov x20, #0                // length

read_name:
    mov x8, #63
    mov x0, #0
    adr x1, tmpbyte
    mov x2, #1
    svc #0
    adr x3, tmpbyte
    ldrb w4, [x3]
    cmp w4, #0x0A
    b.eq name_done
    cmp w4, #0x0D
    b.eq name_done
    // echo
    mov x8, #64
    mov x0, #1
    adr x1, tmpbyte
    mov x2, #1
    svc #0
    cmp x20, #15
    b.ge read_name
    strb w4, [x19]
    add x19, x19, #1
    add x20, x20, #1
    b read_name

name_done:
    mov w4, #0
    strb w4, [x19]             // null-terminate
    // echo newline
    mov x8, #64
    mov x0, #1
    adr x1, newline
    mov x2, #1
    svc #0

    // open(pathbuf) — syscall 56 (openat, we just use path in x0)
    mov x8, #56
    adr x0, pathbuf
    svc #0
    cmp x0, #0
    b.lt err_open
    mov x21, x0                // save fd

read_file:
    mov x8, #63
    mov x0, x21
    adr x1, filebuf
    mov x2, #4096
    svc #0
    cmp x0, #0
    b.le done_read

    // write what we read
    mov x2, x0                 // len
    mov x8, #64
    mov x0, #1
    adr x1, filebuf
    svc #0
    b read_file

done_read:
    // close(fd)
    mov x8, #57
    mov x0, x21
    svc #0

    // exit(0)
    mov x8, #93
    mov x0, #0
    svc #0

err_open:
    mov x8, #64
    mov x0, #1
    adr x1, err_msg
    mov x2, #10
    svc #0
    mov x8, #93
    mov x0, #1
    svc #0

.data
file_prompt: .ascii "file: "
newline:     .ascii "\n"
err_msg:     .ascii "not found\n"
pathbuf:     .byte '/'
             .space 16, 0
tmpbyte:     .byte 0

.bss
filebuf:     .space 4096
