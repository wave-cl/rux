/// aarch64 context switch: save/restore callee-saved registers + stack swap.
///
/// Callee-saved: x19-x28, x29 (FP), x30 (LR), SP.
/// context_switch saves these on the old stack, swaps SP, restores from new stack.

core::arch::global_asm!(r#"
.global context_switch
context_switch:
    // context_switch(old_sp: *mut usize, new_sp: usize)
    // x0 = pointer to save old SP
    // x1 = new SP to switch to

    // Save callee-saved registers on old stack
    stp     x19, x20, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!
    stp     x25, x26, [sp, #-16]!
    stp     x27, x28, [sp, #-16]!
    stp     x29, x30, [sp, #-16]!

    // Save old SP
    mov     x9, sp
    str     x9, [x0]

    // Switch to new stack
    mov     sp, x1

    // Restore callee-saved registers from new stack
    ldp     x29, x30, [sp], #16
    ldp     x27, x28, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x19, x20, [sp], #16

    // Return to new task (x30/LR was restored)
    ret
"#);

extern "C" {
    pub fn context_switch(old_sp: *mut usize, new_sp: usize);
}

/// Fork child return trampoline.
/// context_switch's `ret` jumps here (via LR). The child's kernel stack
/// has a full exception frame (272 bytes). We do restore_context + eret.
core::arch::global_asm!(r#"
.global fork_child_eret
fork_child_eret:
    // SP points to the exception frame (272 bytes)
    ldp     x30, x10, [sp, #240]
    ldr     x11, [sp, #256]
    msr     elr_el1, x10
    msr     spsr_el1, x11
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
    eret
"#);

extern "C" {
    pub fn fork_child_eret();
}

/// Initialize a new kernel stack for a task.
/// Pushes a callee-saved register frame so that context_switch's first
/// switch into this task will "return" to `entry`.
pub unsafe fn init_task_stack(stack_top: usize, entry: usize, _arg: usize) -> usize {
    let mut sp = stack_top & !0xF; // ensure 16-byte alignment

    // 6 pairs × 16 bytes = 96
    sp -= 96;

    // Layout matches context_switch's ldp order:
    //   [SP+0]  = x29 (FP), x30 (LR)  — first popped
    //   [SP+16] = x27, x28
    //   ...
    //   [SP+80] = x19, x20             — last popped
    let p = sp as *mut usize;
    *p.add(0) = 0;          // x29 (FP)
    *p.add(1) = entry;      // x30 (LR) = entry point
    for i in 2..12 { *p.add(i) = 0; } // x27-x20, x19

    sp
}

unsafe impl rux_arch::ContextOps for super::Aarch64 {
    unsafe fn context_switch(old_sp: *mut usize, new_sp: usize) {
        context_switch(old_sp, new_sp)
    }
    unsafe fn init_task_stack(stack_top: usize, entry: usize, arg: usize) -> usize {
        init_task_stack(stack_top, entry, arg)
    }
}
