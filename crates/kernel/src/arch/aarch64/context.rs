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
