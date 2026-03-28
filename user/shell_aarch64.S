.global _start
_start:
    // ── Command 1: /hello ───────────────────────────
    // write(1, "rux$ ", 5)
    mov x8, #64
    mov x0, #1
    adr x1, prompt
    mov x2, #5
    svc #0

    // vfork()
    mov x8, #220
    svc #0
    cbz x0, child1

    // parent: wait4
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

    // ── Command 2: /count ───────────────────────────
    // write(1, "rux$ ", 5)
    mov x8, #64
    mov x0, #1
    adr x1, prompt
    mov x2, #5
    svc #0

    // vfork()
    mov x8, #220
    svc #0
    cbz x0, child2

    // parent: wait4
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

    // exit(0)
    mov x8, #93
    mov x0, #0
    svc #0

child1:
    mov x8, #221
    adr x0, hello_path
    svc #0
    // unreachable
    mov x8, #93
    mov x0, #1
    svc #0

child2:
    mov x8, #221
    adr x0, count_path
    svc #0
    // unreachable
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
