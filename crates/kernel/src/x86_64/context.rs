/// Context switch for x86_64.
///
/// Saves callee-saved registers (rbx, rbp, r12-r15) + rsp onto the old
/// stack, swaps to the new stack, restores callee-saved registers, returns.
/// The return address on each stack determines where execution resumes.
///
/// This follows the System V AMD64 ABI: the caller-saved registers
/// (rax, rcx, rdx, rsi, rdi, r8-r11) are already saved by the calling
/// convention before we get here.

/// Saved context for a kernel task. Stored on the task's kernel stack.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SwitchContext {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rip: u64, // return address (pushed by call instruction)
}

impl SwitchContext {
    /// Create an initial context for a new task that will "return" to `entry`.
    pub const fn new(entry: u64) -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            rbp: 0,
            rip: entry,
        }
    }
}

// The actual switch is in assembly
core::arch::global_asm!(r#"
.global context_switch
context_switch:
    // context_switch(old_rsp: *mut u64, new_rsp: u64)
    // rdi = pointer to old task's saved RSP
    // rsi = new task's saved RSP

    // Save callee-saved registers on the OLD stack
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    // Save old RSP
    movq %rsp, (%rdi)

    // Switch to new stack
    movq %rsi, %rsp

    // Restore callee-saved registers from the NEW stack
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp

    // Return — pops RIP from the new stack, resuming the new task
    retq
"#, options(att_syntax));

extern "C" {
    /// Switch from the current task to another.
    /// - `old_rsp`: pointer to a u64 where the current RSP will be saved
    /// - `new_rsp`: the RSP value to switch to (previously saved by this function)
    pub fn context_switch(old_rsp: *mut u64, new_rsp: u64);
}

/// Initialize a new kernel stack for a task that will start at `entry`.
///
/// Pushes a SwitchContext-compatible frame onto the stack so that
/// context_switch's `ret` will jump to `entry`.
///
/// Returns the initial RSP value to pass to context_switch as `new_rsp`.
pub unsafe fn init_task_stack(stack_top: u64, entry: u64, _arg: u64) -> u64 {
    let mut sp = stack_top;

    // The entry function is the "return address" that context_switch's retq pops.
    // After context_switch pops r15-r12, rbx, rbp (6 registers), it does retq
    // which pops the next value as RIP.

    // Push the entry point as the return address
    sp -= 8;
    *(sp as *mut u64) = entry;

    // Push callee-saved registers (all zero for a new task)
    sp -= 8; *(sp as *mut u64) = 0; // rbp
    sp -= 8; *(sp as *mut u64) = 0; // rbx
    sp -= 8; *(sp as *mut u64) = 0; // r12
    sp -= 8; *(sp as *mut u64) = 0; // r13
    sp -= 8; *(sp as *mut u64) = 0; // r14
    sp -= 8; *(sp as *mut u64) = 0; // r15

    sp
}
