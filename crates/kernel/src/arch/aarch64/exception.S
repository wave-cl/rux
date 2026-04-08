/*
 * aarch64 exception vector table.
 *
 * 16 entries, 128 bytes each (32 instructions max), 2048 bytes total.
 * Must be aligned to 2048 bytes (0x800).
 *
 * Layout (4 groups × 4 exception types):
 *   Group 0: Current EL with SP_EL0 (unused in kernel)
 *   Group 1: Current EL with SP_ELx (kernel → kernel exceptions)
 *   Group 2: Lower EL, AArch64 (user → kernel)
 *   Group 3: Lower EL, AArch32 (not used)
 *
 * Each type: Synchronous, IRQ, FIQ, SError
 */

.section .text.vectors
.balign 2048
.global exception_vectors
exception_vectors:

/* ── Group 0: Current EL with SP_EL0 (not used) ────────────────────── */
.balign 128
    b       unhandled_exception     /* Synchronous */
.balign 128
    b       unhandled_exception     /* IRQ */
.balign 128
    b       unhandled_exception     /* FIQ */
.balign 128
    b       unhandled_exception     /* SError */

/* ── Group 1: Current EL with SP_ELx (kernel exceptions/IRQs) ──────── */
.balign 128
    b       sync_el1_handler        /* Synchronous (page fault, SVC, etc.) */
.balign 128
    b       irq_el1_handler         /* IRQ (timer, device interrupts) */
.balign 128
    b       unhandled_exception     /* FIQ */
.balign 128
    b       unhandled_exception     /* SError */

/* ── Group 2: Lower EL, AArch64 (user → kernel) ───────────────────── */
.balign 128
    b       sync_el0_handler        /* Synchronous (SVC from user) */
.balign 128
    b       irq_el0_handler         /* IRQ during user mode */
.balign 128
    b       unhandled_exception     /* FIQ */
.balign 128
    b       unhandled_exception     /* SError */

/* ── Group 3: Lower EL, AArch32 (not used) ─────────────────────────── */
.balign 128
    b       unhandled_exception     /* Synchronous */
.balign 128
    b       unhandled_exception     /* IRQ */
.balign 128
    b       unhandled_exception     /* FIQ */
.balign 128
    b       unhandled_exception     /* SError */

/* ── Exception handlers ─────────────────────────────────────────────── */

/*
 * Save all general-purpose registers + ELR_EL1 + SPSR_EL1 onto the stack.
 * This creates a 34-register frame (272 bytes) matching CpuContext layout.
 */
.macro save_context
    sub     sp, sp, #272
    stp     x0,  x1,  [sp, #0]
    stp     x2,  x3,  [sp, #16]
    stp     x4,  x5,  [sp, #32]
    stp     x6,  x7,  [sp, #48]
    stp     x8,  x9,  [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    mrs     x10, elr_el1
    mrs     x11, spsr_el1
    stp     x30, x10, [sp, #240]    /* x30 (lr) + elr_el1 */
    str     x11, [sp, #256]         /* spsr_el1 */
.endm

.macro restore_context
    ldp     x30, x10, [sp, #240]
    ldr     x11, [sp, #256]
    msr     elr_el1, x10
    msr     spsr_el1, x11
    isb
    ldp     x0,  x1,  [sp, #0]
    ldp     x2,  x3,  [sp, #16]
    ldp     x4,  x5,  [sp, #32]
    ldp     x6,  x7,  [sp, #48]
    ldp     x8,  x9,  [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    add     sp, sp, #272
.endm

sync_el1_handler:
    save_context
    mov     x0, #0                  /* type = sync */
    mrs     x1, esr_el1             /* exception syndrome register */
    mrs     x2, far_el1             /* fault address register */
    mov     x3, sp                  /* frame pointer */
    bl      exception_dispatch
    restore_context
    eret

irq_el1_handler:
    save_context
    /* Switch to per-CPU IRQ stack (Linux call_on_irq_stack approach).
       Exception frame stays on the task stack. Handler runs on IRQ stack.
       This allows safe context_switch from the handler without corrupting
       the task's exception frame. */
    mov     x19, sp                         /* save task stack (callee-saved) */
    mrs     x20, tpidr_el1                  /* percpu base */
    ldr     x21, [x20, #56]                 /* percpu.irq_stack_top (offset 56) */
    mov     sp, x21                         /* switch to IRQ stack */
    mov     x0, #1                          /* type = IRQ */
    mov     x1, #0
    mov     x2, #0
    mov     x3, x19                         /* frame pointer = task stack SP */
    bl      exception_dispatch
    mov     sp, x19                         /* restore task stack */
    /* Check preemption (on task stack, exception frame is below us) */
    bl      aarch64_isr_check_preempt
    restore_context
    eret

sync_el0_handler:
    save_context
    mov     x0, #2                  /* type = sync from EL0 (user) */
    mrs     x1, esr_el1
    mrs     x2, far_el1
    mov     x3, sp                  /* frame pointer */
    bl      exception_dispatch
    restore_context
    eret

irq_el0_handler:
    save_context
    /* Switch to per-CPU IRQ stack (same as irq_el1_handler) */
    mov     x19, sp
    mrs     x20, tpidr_el1
    ldr     x21, [x20, #56]                 /* percpu.irq_stack_top */
    mov     sp, x21
    mov     x0, #3                          /* type = IRQ from EL0 (user) */
    mov     x1, #0
    mov     x2, #0
    mov     x3, x19
    bl      exception_dispatch
    mov     sp, x19                         /* restore task stack */
    bl      aarch64_isr_check_preempt
    restore_context
    eret

unhandled_exception:
    save_context
    mov     x0, #99                 /* type = unhandled */
    mrs     x1, esr_el1
    mrs     x2, far_el1
    mov     x3, sp
    bl      exception_dispatch
    restore_context
    eret
