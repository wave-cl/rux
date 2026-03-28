.global _start
_start:
    // write(1, prompt, 5) — "rux$ "
    mov x8, #64         // write
    mov x0, #1          // fd: stdout
    adr x1, prompt      // buf
    mov x2, #5          // len
    svc #0

    // vfork()
    mov x8, #220        // vfork (clone with CLONE_VFORK)
    svc #0

    // x0 = 0 in child, >0 in parent
    cbz x0, child

parent:
    // wait4(child_pid, NULL, 0, NULL)
    // x0 already has child PID
    mov x8, #260        // wait4
    mov x1, #0          // status ptr
    mov x2, #0          // options
    mov x3, #0          // rusage
    svc #0

    // write(1, done_msg, 10) — "rux$ done\n"
    mov x8, #64
    mov x0, #1
    adr x1, done_msg
    mov x2, #10
    svc #0

    // exit(0)
    mov x8, #93
    mov x0, #0
    svc #0

child:
    // exec("/hello")
    mov x8, #221        // execve
    adr x0, hello_path  // path
    svc #0

    // Should not reach here
    mov x8, #93
    mov x0, #1
    svc #0

prompt:
    .ascii "rux$ "
done_msg:
    .ascii "rux$ done\n"
hello_path:
    .asciz "/hello"
