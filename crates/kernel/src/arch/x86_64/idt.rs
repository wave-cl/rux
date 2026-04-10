/// Interrupt Descriptor Table for x86_64.
///
/// 256 entries, each 16 bytes. Vectors 0-31 are CPU exceptions,
/// 32+ are hardware IRQs and software interrupts.

use super::gdt::KERNEL_CS;

/// IDT gate descriptor (16 bytes).
#[derive(Clone, Copy)]
#[repr(C)]
struct IdtEntry {
    offset_low: u16,    // bits 0-15 of handler address
    selector: u16,      // code segment selector
    ist: u8,            // interrupt stack table index (0 = none)
    type_attr: u8,      // type (0xE = interrupt gate, 0xF = trap gate) + DPL + Present
    offset_mid: u16,    // bits 16-31
    offset_high: u32,   // bits 32-63
    reserved: u32,
}

impl IdtEntry {
    const EMPTY: Self = Self {
        offset_low: 0, selector: 0, ist: 0, type_attr: 0,
        offset_mid: 0, offset_high: 0, reserved: 0,
    };

    /// Create an interrupt gate (clears IF on entry).
    fn interrupt_gate(handler: u64, cs: u16, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: cs,
            ist,
            type_attr: 0x8E, // P=1, DPL=0, type=0xE (interrupt gate)
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }

    /// Create a trap gate callable from user mode (DPL=3).
    fn trap_gate_user(handler: u64, cs: u16, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: cs,
            ist,
            type_attr: 0xEF, // P=1, DPL=3, type=0xF (trap gate, user-callable)
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }

    /// Create a trap gate (does NOT clear IF on entry).
    fn trap_gate(handler: u64, cs: u16, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: cs,
            ist,
            type_attr: 0x8F, // P=1, DPL=0, type=0xF (trap gate)
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

/// IDTR pointer structure.
#[repr(C, packed)]
struct IdtPtr {
    limit: u16,
    base: u64,
}

const IDT_ENTRIES: usize = 256;

static mut IDT: [IdtEntry; IDT_ENTRIES] = [IdtEntry::EMPTY; IDT_ENTRIES];

// Generic interrupt/exception stub that saves registers and calls
// a Rust handler. Each vector gets a small trampoline that pushes
// the vector number, then jumps to the common handler.
//
// The common handler saves all GPRs, calls `interrupt_dispatch(vector, frame)`,
// restores GPRs, and iretq's.

// Generate 256 interrupt stubs via assembly
core::arch::global_asm!(r#"
// Common interrupt handler: saves all GPRs, calls Rust dispatch
.global interrupt_common
interrupt_common:
    // At this point, stack has: [SS, RSP, RFLAGS, CS, RIP, error_code, vector_num]
    // (error_code and vector_num pushed by the per-vector stubs)

    // Save all general-purpose registers
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    // Call Rust handler: interrupt_dispatch(vector: u64, error_code: u64, frame: *const u8)
    movq 120(%rsp), %rdi          // vector number (15 regs * 8 = 120 bytes up)
    movq 128(%rsp), %rsi          // error code
    movq %rsp, %rdx               // pointer to saved registers

    call interrupt_dispatch

    // Check preemption (safe for both kernel and user mode returns).
    // interrupt_dispatch ran on the IRQ stack; we're back on the task stack
    // with the exception frame intact below us.
    call isr_check_preempt

    // Restore registers — fork_child_return jumps here
    .global interrupt_return
interrupt_return:
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax

    // Remove vector number and error code from stack
    addq $16, %rsp

    iretq
"#, options(att_syntax));

// Macro to generate per-vector stubs. Exceptions with error codes (8, 10-14, 17, 21, 29, 30)
// have the CPU push the error code; others need a dummy 0 pushed for uniform stack layout.
macro_rules! isr_stub {
    // No error code — push dummy 0
    (no_err, $vec:expr) => {
        core::arch::global_asm!(
            concat!(".global isr_stub_", stringify!($vec)),
            concat!("isr_stub_", stringify!($vec), ":"),
            "pushq $0",                          // dummy error code
            concat!("pushq $", stringify!($vec)), // vector number
            "jmp interrupt_common",
            options(att_syntax),
        );
    };
    // Has error code (pushed by CPU)
    (err, $vec:expr) => {
        core::arch::global_asm!(
            concat!(".global isr_stub_", stringify!($vec)),
            concat!("isr_stub_", stringify!($vec), ":"),
            concat!("pushq $", stringify!($vec)), // vector number (error code already on stack)
            "jmp interrupt_common",
            options(att_syntax),
        );
    };
}

// CPU exceptions (vectors 0-31)
isr_stub!(no_err, 0);   // Divide by zero
isr_stub!(no_err, 1);   // Debug
isr_stub!(no_err, 2);   // NMI
isr_stub!(no_err, 3);   // Breakpoint
isr_stub!(no_err, 4);   // Overflow
isr_stub!(no_err, 5);   // Bound range exceeded
isr_stub!(no_err, 6);   // Invalid opcode
isr_stub!(no_err, 7);   // Device not available
isr_stub!(err,    8);   // Double fault (has error code)
isr_stub!(no_err, 9);   // Coprocessor segment overrun
isr_stub!(err,    10);  // Invalid TSS
isr_stub!(err,    11);  // Segment not present
isr_stub!(err,    12);  // Stack segment fault
isr_stub!(err,    13);  // General protection fault
isr_stub!(err,    14);  // Page fault
isr_stub!(no_err, 15);  // Reserved
isr_stub!(no_err, 16);  // x87 floating point
isr_stub!(err,    17);  // Alignment check
isr_stub!(no_err, 18);  // Machine check
isr_stub!(no_err, 19);  // SIMD floating point
isr_stub!(no_err, 20);  // Virtualization
isr_stub!(err,    21);  // Control protection
isr_stub!(no_err, 22);  // Reserved
isr_stub!(no_err, 23);
isr_stub!(no_err, 24);
isr_stub!(no_err, 25);
isr_stub!(no_err, 26);
isr_stub!(no_err, 27);
isr_stub!(no_err, 28);
isr_stub!(err,    29);  // VMM communication
isr_stub!(err,    30);  // Security exception
isr_stub!(no_err, 31);

// Hardware IRQs (vectors 32-47)
isr_stub!(no_err, 32);  // Timer
isr_stub!(no_err, 33);  // Keyboard
isr_stub!(no_err, 34);
isr_stub!(no_err, 35);
isr_stub!(no_err, 36);
isr_stub!(no_err, 37);
isr_stub!(no_err, 38);
isr_stub!(no_err, 39);
isr_stub!(no_err, 40);
isr_stub!(no_err, 41);
isr_stub!(no_err, 42);
isr_stub!(no_err, 43);
isr_stub!(no_err, 44);
isr_stub!(no_err, 45);
isr_stub!(no_err, 46);
isr_stub!(no_err, 47);

// AP LAPIC timer
isr_stub!(no_err, 48);

// Software interrupt for syscalls
isr_stub!(no_err, 128); // INT 0x80

// Stub addresses — used to fill the IDT
extern "C" {
    fn isr_stub_0(); fn isr_stub_1(); fn isr_stub_2(); fn isr_stub_3();
    fn isr_stub_4(); fn isr_stub_5(); fn isr_stub_6(); fn isr_stub_7();
    fn isr_stub_8(); fn isr_stub_9(); fn isr_stub_10(); fn isr_stub_11();
    fn isr_stub_12(); fn isr_stub_13(); fn isr_stub_14(); fn isr_stub_15();
    fn isr_stub_16(); fn isr_stub_17(); fn isr_stub_18(); fn isr_stub_19();
    fn isr_stub_20(); fn isr_stub_21(); fn isr_stub_22(); fn isr_stub_23();
    fn isr_stub_24(); fn isr_stub_25(); fn isr_stub_26(); fn isr_stub_27();
    fn isr_stub_28(); fn isr_stub_29(); fn isr_stub_30(); fn isr_stub_31();
    fn isr_stub_32(); fn isr_stub_33(); fn isr_stub_34(); fn isr_stub_35();
    fn isr_stub_36(); fn isr_stub_37(); fn isr_stub_38(); fn isr_stub_39();
    fn isr_stub_40(); fn isr_stub_41(); fn isr_stub_42(); fn isr_stub_43();
    fn isr_stub_44(); fn isr_stub_45(); fn isr_stub_46(); fn isr_stub_47();
    fn isr_stub_48();
    fn isr_stub_128();
}

/// Get the address of an ISR stub by vector number.
fn isr_stub_addr(vector: usize) -> u64 {
    let stubs: [unsafe extern "C" fn(); 48] = [
        isr_stub_0, isr_stub_1, isr_stub_2, isr_stub_3,
        isr_stub_4, isr_stub_5, isr_stub_6, isr_stub_7,
        isr_stub_8, isr_stub_9, isr_stub_10, isr_stub_11,
        isr_stub_12, isr_stub_13, isr_stub_14, isr_stub_15,
        isr_stub_16, isr_stub_17, isr_stub_18, isr_stub_19,
        isr_stub_20, isr_stub_21, isr_stub_22, isr_stub_23,
        isr_stub_24, isr_stub_25, isr_stub_26, isr_stub_27,
        isr_stub_28, isr_stub_29, isr_stub_30, isr_stub_31,
        isr_stub_32, isr_stub_33, isr_stub_34, isr_stub_35,
        isr_stub_36, isr_stub_37, isr_stub_38, isr_stub_39,
        isr_stub_40, isr_stub_41, isr_stub_42, isr_stub_43,
        isr_stub_44, isr_stub_45, isr_stub_46, isr_stub_47,
    ];
    if vector < stubs.len() {
        stubs[vector] as u64
    } else {
        0
    }
}

/// Initialize the IDT with all exception and IRQ handlers.
pub unsafe fn init() {
    // Set up exception handlers (0-31) as trap gates
    for i in 0..32 {
        IDT[i] = IdtEntry::trap_gate(isr_stub_addr(i), KERNEL_CS, 0);
    }
    // Double fault (8) uses IST1 for a known-good stack
    IDT[8] = IdtEntry::trap_gate(isr_stub_addr(8), KERNEL_CS, 1);

    // Set up IRQ handlers (32-47) as interrupt gates (clear IF)
    for i in 32..48 {
        IDT[i] = IdtEntry::interrupt_gate(isr_stub_addr(i), KERNEL_CS, 0);
    }

    // Vector 48 — AP LAPIC timer
    IDT[48] = IdtEntry::interrupt_gate(isr_stub_48 as *const () as u64, KERNEL_CS, 0);

    // INT 0x80 — syscall trap gate, DPL=3 (callable from user space)
    IDT[128] = IdtEntry::trap_gate_user(isr_stub_128 as *const () as u64, KERNEL_CS, 0);

    // Load IDT
    let idt_ptr = IdtPtr {
        limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
        base: (&raw const IDT) as *const u8 as u64,
    };

    core::arch::asm!(
        "lidt [{}]",
        in(reg) &idt_ptr,
        options(nostack)
    );
}

/// Load the IDT on an AP (reuses the BSP's IDT — it's shared).
pub unsafe fn load() {
    let idt_ptr = IdtPtr {
        limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
        base: (&raw const IDT) as *const u8 as u64,
    };
    core::arch::asm!("lidt [{}]", in(reg) &idt_ptr, options(nostack));
}

/// Called from interrupt_common when returning to user mode.
/// If need_resched is set, perform a context switch before iretq.
/// Safe because we are returning to user mode (not nested in kernel code),
/// and TSS.rsp0 is updated per-task so each task's ISR frame is on its own stack.
#[no_mangle]
pub unsafe extern "C" fn isr_check_preempt() {
    if crate::arch::preemptible() {
        let cpu = crate::percpu::cpu_id() as u32;
        // On TCG (no GS-based per-CPU), only BSP can ISR-preempt safely.
        // AP preemption would overwrite shared globals (CURRENT_KSTACK_TOP, etc).
        #[cfg(target_arch = "x86_64")]
        if cpu != 0 && !super::syscall::GS_PERCPU_ACTIVE { return; }
        let sched = crate::scheduler::get();
        if sched.need_resched & (1u64 << cpu) != 0 {
            crate::arch::preempt_disable();
            sched.schedule();
            crate::arch::preempt_enable();
        }
    }
}

/// Run a function on the per-CPU IRQ stack (Linux call_on_stack approach).
/// Saves RSP at the top of the IRQ stack, switches, calls func, restores via popq.
#[inline(always)]
unsafe fn call_on_irq_stack(func: unsafe fn(u64, u64, *mut u8), vector: u64, error_code: u64, frame: *mut u8) {
    // Per-CPU IRQ stack. percpu.irq_stack_top is set per-AP at boot.
    // Fallback to global for BSP early boot (before percpu is fully initialized).
    let pc_top = crate::percpu::this_cpu().irq_stack_top;
    let irq_stack_top = if pc_top != 0 { pc_top } else { super::syscall::CURRENT_IRQ_STACK_TOP };
    if irq_stack_top == 0 {
        // IRQ stack not initialized yet (early boot) — run on current stack
        func(vector, error_code, frame);
        return;
    }
    core::arch::asm!(
        "mov [{}], rsp",          // save current RSP at top of IRQ stack
        "mov rsp, {}",            // switch to IRQ stack
        "call {}",                // call handler (on IRQ stack)
        "pop rsp",                // restore original RSP
        in(reg) irq_stack_top,
        in(reg) irq_stack_top,
        sym interrupt_dispatch_inner,
        in("rdi") vector,
        in("rsi") error_code,
        in("rdx") frame,
        clobber_abi("C"),
    );
}

/// Rust dispatch function called from the assembly common handler.
#[no_mangle]
pub extern "C" fn interrupt_dispatch(vector: u64, error_code: u64, frame: *mut u8) {
    // Non-exception vectors (IRQs): run on IRQ stack
    if vector >= 32 {
        unsafe { call_on_irq_stack(interrupt_dispatch_inner, vector, error_code, frame); }
        return;
    }
    // Exceptions (vectors 0-31): run on current stack (may need task stack for page fault handling)
    unsafe { interrupt_dispatch_inner(vector, error_code, frame); }
}

/// Inner dispatch — runs on IRQ stack for IRQs, task stack for exceptions.
#[no_mangle]
unsafe fn interrupt_dispatch_inner(vector: u64, error_code: u64, frame: *mut u8) {
    match vector {
        0 => panic!("Division by zero"),
        6 | 13 => {
            // frame points to saved GPRs; RIP is at offset 136 (15 GPRs + vec + errcode)
            let rip = unsafe { *((frame as *const u64).add(17)) };
            use rux_arch::ConsoleOps;
            let name = if vector == 6 { "Invalid opcode (#UD)" } else { "General protection fault (#GP)" };
            crate::arch::Arch::write_str("rux: EXCEPTION: ");
            crate::arch::Arch::write_str(name);
            crate::arch::Arch::write_str("\n  RIP=0x");
            let mut buf = [0u8; 16];
            crate::arch::Arch::write_bytes(rux_klib::fmt::usize_to_hex(&mut buf, rip as usize));
            crate::arch::Arch::write_str(" error_code=0x");
            crate::arch::Arch::write_bytes(rux_klib::fmt::usize_to_hex(&mut buf, error_code as usize));
            crate::arch::Arch::write_str("\n");
            super::exit::exit_qemu(super::exit::EXIT_FAILURE);
        }
        8 => panic!("Double fault (error_code={:#x})", error_code),
        14 => {
            let cr2: u64;
            unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nostack)); }
            let user = error_code & 4 != 0;
            let write = error_code & 2 != 0;

            // Shared fault resolution: COW → demand page → SIGSEGV
            if unsafe { crate::demand_paging::handle_user_fault(cr2, write) } {
                return;
            }

            // Unresolvable user-space fault → kill process (SIGSEGV)
            if cr2 < 0x0000_8000_0000_0000u64 {
                unsafe {
                    // Suppress log for NULL dereferences (addr < 4096).
                    // Common in thread cleanup during exit_group (e.g., Ruby GC).
                    if cr2 >= 0x1000 {
                        use rux_arch::ConsoleOps;
                        let mut hb = [0u8; 16];
                        let rip = *((frame as *const u64).add(17));
                        crate::arch::Arch::write_str("rux: SIGSEGV addr=0x");
                        crate::arch::Arch::write_bytes(rux_klib::fmt::usize_to_hex(&mut hb, cr2 as usize));
                        crate::arch::Arch::write_str(" rip=0x");
                        crate::arch::Arch::write_bytes(rux_klib::fmt::usize_to_hex(&mut hb, rip as usize));
                        if !user { crate::arch::Arch::write_str(" KERNEL"); }
                        crate::arch::Arch::write_str("\n");
                    }
                    crate::syscall::linux::exit_group(139);
                }
            }

            // Kernel-mode fault — dump and panic
            unsafe {
                let cr3: u64;
                core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
                let r = frame as *const u64;
                let w = |s: &str| super::console::write_str(s);
                let h = |v: usize| {
                    let mut b = [0u8; 16];
                    super::console::write_str("0x");
                    super::console::write_bytes(rux_klib::fmt::usize_to_hex(&mut b, v));
                };
                w(if user { "\n=== USER PAGE FAULT ===\n" } else { "\n=== KERNEL PAGE FAULT ===\n" });
                w("  fault addr: "); h(cr2 as usize);
                w("  err: "); h(error_code as usize); super::console::write_byte(b'\n');
                w("  rip: "); h(*r.add(17) as usize);
                w("  rsp: "); h(*r.add(20) as usize); super::console::write_byte(b'\n');
                w("  cr3: "); h(cr3 as usize); super::console::write_byte(b'\n');
                // Walk page table to show PTE for faulting address
                let l4_idx = (cr2 as usize >> 39) & 0x1FF;
                let l3_idx = (cr2 as usize >> 30) & 0x1FF;
                let l2_idx = (cr2 as usize >> 21) & 0x1FF;
                let l1_idx = (cr2 as usize >> 12) & 0x1FF;
                let l4 = cr3 as *const u64;
                let l4e = *l4.add(l4_idx);
                w("  L4["); h(l4_idx); w("]="); h(l4e as usize); super::console::write_byte(b'\n');
                if l4e & 1 != 0 {
                    let l3 = (l4e & 0x000F_FFFF_FFFF_F000) as *const u64;
                    let l3e = *l3.add(l3_idx);
                    w("  L3["); h(l3_idx); w("]="); h(l3e as usize); super::console::write_byte(b'\n');
                    if l3e & 1 != 0 && l3e & (1<<7) == 0 {
                        let l2 = (l3e & 0x000F_FFFF_FFFF_F000) as *const u64;
                        let l2e = *l2.add(l2_idx);
                        w("  L2["); h(l2_idx); w("]="); h(l2e as usize); super::console::write_byte(b'\n');
                        if l2e & 1 != 0 && l2e & (1<<7) == 0 {
                            let l1 = (l2e & 0x000F_FFFF_FFFF_F000) as *const u64;
                            let l1e = *l1.add(l1_idx);
                            w("  L1["); h(l1_idx); w("]="); h(l1e as usize); super::console::write_byte(b'\n');
                        }
                    }
                }
            }
            panic!("page fault");
        }
        32 => {
            // BSP PIT timer tick
            super::pit::tick();
            unsafe { super::pit::ack(); }
            unsafe {
                crate::task_table::wake_sleepers();
                #[cfg(feature = "net")]
                if rux_net::is_configured() {
                    use rux_arch::TimerOps;
                    rux_net::poll(crate::arch::Arch::ticks());
                    // Wake tasks sleeping in poll() — they'll re-check their fds
                    if crate::task_table::has_poll_waiters() {
                        crate::task_table::poll_wake_all();
                    }
                }

                crate::scheduler::locked_tick(1_000_000);
                // Preemption handled by isr_check_preempt in interrupt_common
                // assembly — runs on the task stack after call_on_irq_stack returns.
            }
        }
        48 => {
            // AP LAPIC timer tick
            unsafe { super::apic::eoi(); }
            unsafe {
                crate::scheduler::locked_tick(1_000_000);
                // Preemption handled by isr_check_preempt in interrupt_common.
            }
        }
        49 => {
            // Reschedule IPI (Linux RESCHEDULE_VECTOR).
            // Handler just ACKs — isr_check_preempt does the rescheduling.
            unsafe { super::apic::eoi(); }
        }
        128 => {
            // INT 0x80 — syscall from user space
            super::syscall::handle_syscall(vector, error_code, frame);
        }
        36 => {
            // COM1 serial receive interrupt (IRQ 4)
            unsafe { super::console::serial_irq(); }
            unsafe { super::pit::ack(); } // EOI to PIC
        }
        _ => {
            crate::arch::x86_64::console::write_str("INT: vector=");
            let mut buf = [0u8; 10];
            crate::arch::x86_64::console::write_str(rux_klib::fmt::u32_to_str(&mut buf, vector as u32));
            crate::arch::x86_64::console::write_byte(b'\n');
        }
    }
}
