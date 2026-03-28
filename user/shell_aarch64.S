.global _start
_start:
    // ── Run /hello ──────────────────────────────────
    adr x19, hello_path
    bl  run_command

    // ── Run /count ──────────────────────────────────
    adr x19, count_path
    bl  run_command

    // exit(0)
    mov x8, #93
    mov x0, #0
    svc #0

// Subroutine: print prompt, vfork, child execs *x19, parent waits
run_command:
    // Save link register
    str x30, [sp, #-16]!

    // write(1, "rux$ ", 5)
    mov x8, #64
    mov x0, #1
    adr x1, prompt
    mov x2, #5
    svc #0

    // vfork()
    mov x8, #220
    svc #0
    cbz x0, .child

    // parent: wait4(child_pid)
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

    ldr x30, [sp], #16
    ret

.child:
    // exec(x19)
    mov x8, #221
    mov x0, x19
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
count_path:
    .asciz "/count"
