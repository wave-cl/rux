/// aarch64 context switch: save/restore callee-saved registers + stack swap.
///
/// Callee-saved: x19-x28, x29 (FP), x30 (LR), SP.
/// context_switch saves these on the old stack, swaps SP, restores from new stack.

core::arch::global_asm!(r#"
.global context_switch
context_switch:
    // context_switch(old_sp: *mut u64, new_sp: u64)
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
    pub fn context_switch(old_sp: *mut u64, new_sp: u64);
}

/// Initialize a new kernel stack for a task.
/// Pushes a callee-saved register frame so that context_switch's first
/// switch into this task will "return" to `entry`.
pub unsafe fn init_task_stack(stack_top: u64, entry: u64, _arg: u64) -> u64 {
    let mut sp = stack_top & !0xF; // ensure 16-byte alignment

    // context_switch pushes in order: x19+x20, x21+x22, ..., x29+x30
    // So x29+x30 is at the LOWEST address (SP after all pushes).
    // We must lay out the stack to match the POP order:
    //   [SP+0]  = x29, x30  (first popped)
    //   [SP+16] = x27, x28
    //   [SP+32] = x25, x26
    //   [SP+48] = x23, x24
    //   [SP+64] = x21, x22
    //   [SP+80] = x19, x20  (last popped)

    sp -= 96; // 6 pairs × 16 bytes = 96

    *((sp + 0) as *mut u64) = 0;          // x29 (FP)
    *((sp + 8) as *mut u64) = entry;      // x30 (LR) = entry point
    *((sp + 16) as *mut u64) = 0;         // x27
    *((sp + 24) as *mut u64) = 0;         // x28
    *((sp + 32) as *mut u64) = 0;         // x25
    *((sp + 40) as *mut u64) = 0;         // x26
    *((sp + 48) as *mut u64) = 0;         // x23
    *((sp + 56) as *mut u64) = 0;         // x24
    *((sp + 64) as *mut u64) = 0;         // x21
    *((sp + 72) as *mut u64) = 0;         // x22
    *((sp + 80) as *mut u64) = 0;         // x19
    *((sp + 88) as *mut u64) = 0;         // x20

    sp
}

unsafe impl rux_arch::ContextOps for super::Aarch64 {
    unsafe fn context_switch(old_sp: *mut u64, new_sp: u64) {
        context_switch(old_sp, new_sp)
    }
    unsafe fn init_task_stack(stack_top: u64, entry: u64, arg: u64) -> u64 {
        init_task_stack(stack_top, entry, arg)
    }
}
