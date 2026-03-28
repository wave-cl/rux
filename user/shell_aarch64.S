.global _start
_start:
    mov x19, #2             // loop counter: run 2 commands

shell_loop:
    // write(1, "rux$ ", 5)
    mov x8, #64
    mov x0, #1
    adr x1, prompt
    mov x2, #5
    svc #0

    // vfork()
    mov x8, #220
    svc #0

    cbz x0, child

parent:
    // wait4(child_pid, NULL, 0, NULL)
    mov x8, #260
    mov x1, #0
    mov x2, #0
    mov x3, #0
    svc #0

    // write(1, "done\n", 5)
    mov x8, #64
    mov x0, #1
    adr x1, done_msg
    mov x2, #5
    svc #0

    sub x19, x19, #1
    cbnz x19, shell_loop

    // exit(0)
    mov x8, #93
    mov x0, #0
    svc #0

child:
    // exec("/hello")
    mov x8, #221
    adr x0, hello_path
    svc #0

    // exec failed — exit(1)
    mov x8, #93
    mov x0, #1
    svc #0

prompt:
    .ascii "rux$ "
done_msg:
    .ascii "done\n"
hello_path:
    .asciz "/hello"
