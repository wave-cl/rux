/// Kernel buffer for passing exec arguments to the new process.
/// Reads argv/envp from user memory, builds Linux-compatible stack layout.

const MAX_ARGS: usize = 16;
const MAX_STRBUF: usize = 1024;

/// Stored argv strings (null-terminated, packed in a buffer)
static mut ARGV_BUF: [u8; MAX_STRBUF] = [0; MAX_STRBUF];
/// Offsets into ARGV_BUF for each argv string
static mut ARGV_OFFSETS: [usize; MAX_ARGS] = [0; MAX_ARGS];
/// Lengths of each argv string (not including null)
static mut ARGV_LENS: [usize; MAX_ARGS] = [0; MAX_ARGS];
/// Number of argv entries
static mut ARGC: usize = 0;

/// Stored envp strings
static mut ENVP_BUF: [u8; MAX_STRBUF] = [0; MAX_STRBUF];
static mut ENVP_OFFSETS: [usize; MAX_ARGS] = [0; MAX_ARGS];
static mut ENVP_LENS: [usize; MAX_ARGS] = [0; MAX_ARGS];
static mut ENVC: usize = 0;

/// Cmdline buffer: null-separated argv, filled by write_to_stack.
static mut CMDLINE_BUF: [u8; 128] = [0; 128];
static mut CMDLINE_LEN: u8 = 0;

/// Get the last exec'd cmdline (null-separated argv bytes).
pub fn get_cmdline() -> (&'static [u8], u8) {
    unsafe { (&*(&raw const CMDLINE_BUF), *(&raw const CMDLINE_LEN)) }
}

/// Copy the last exec'd environ as null-separated KEY=VALUE pairs into buf.
/// Returns bytes written.
pub fn copy_environ(buf: &mut [u8]) -> usize {
    unsafe {
        let envc = *(&raw const ENVC);
        let mut pos = 0;
        for i in 0..envc {
            let off = ENVP_OFFSETS[i];
            let len = ENVP_LENS[i];
            if pos + len + 1 > buf.len() { break; }
            buf[pos..pos+len].copy_from_slice(&ENVP_BUF[off..off+len]);
            buf[pos+len] = 0; // null separator
            pos += len + 1;
        }
        pos
    }
}

/// Dynamic linking auxv entries (set by exec, cleared for static binaries).
static mut AUXV_PHDR: usize = 0;   // AT_PHDR: address of program headers
static mut AUXV_PHENT: usize = 0;  // AT_PHENT: size of one program header entry
static mut AUXV_PHNUM: usize = 0;  // AT_PHNUM: number of program headers
static mut AUXV_ENTRY: usize = 0;  // AT_ENTRY: binary's original entry point
static mut AUXV_BASE: usize = 0;   // AT_BASE: base address of dynamic linker

/// Set dynamic linking auxv values (called before write_to_stack for dynamic binaries).
pub unsafe fn set_dynamic_auxv(phdr: usize, phent: usize, phnum: usize, entry: usize, base: usize) {
    AUXV_PHDR = phdr;
    AUXV_PHENT = phent;
    AUXV_PHNUM = phnum;
    AUXV_ENTRY = entry;
    AUXV_BASE = base;
}

/// Clear dynamic linking auxv (called for static binaries).
pub unsafe fn clear_dynamic_auxv() {
    AUXV_PHDR = 0;
    AUXV_PHENT = 0;
    AUXV_PHNUM = 0;
    AUXV_ENTRY = 0;
    AUXV_BASE = 0;
}

/// Read argv from user memory (pointer to NULL-terminated array of char*).
/// If argv_ptr is NULL or 0, uses path as argv[0].
pub unsafe fn set_from_user(path: &[u8], argv_ptr: usize, envp_ptr: usize) {
    ARGC = 0;
    ENVC = 0;
    let mut buf_pos = 0usize;

    if argv_ptr != 0 {
        // Read argv[] array from user memory (array of pointer-width entries)
        let argv = argv_ptr as *const usize;
        for i in 0..MAX_ARGS {
            let str_ptr = *argv.add(i);
            if str_ptr == 0 { break; } // NULL terminator

            let cstr = str_ptr as *const u8;
            let mut len = 0usize;
            while *cstr.add(len) != 0 && len < 255 { len += 1; }

            if buf_pos + len + 1 > MAX_STRBUF { break; }

            ARGV_OFFSETS[i] = buf_pos;
            ARGV_LENS[i] = len;
            for j in 0..len {
                ARGV_BUF[buf_pos + j] = *cstr.add(j);
            }
            ARGV_BUF[buf_pos + len] = 0;
            buf_pos += len + 1;
            ARGC += 1;
        }
    }

    // Read envp from user memory
    if envp_ptr > 0x1000 {
        let envp = envp_ptr as *const usize;
        let mut env_pos = 0usize;
        for i in 0..MAX_ARGS {
            let str_ptr = *envp.add(i);
            if str_ptr == 0 { break; }
            let cstr = str_ptr as *const u8;
            let mut len = 0usize;
            while *cstr.add(len) != 0 && len < 255 { len += 1; }
            if env_pos + len + 1 > MAX_STRBUF { break; }
            ENVP_OFFSETS[i] = env_pos;
            ENVP_LENS[i] = len;
            for j in 0..len { ENVP_BUF[env_pos + j] = *cstr.add(j); }
            ENVP_BUF[env_pos + len] = 0;
            env_pos += len + 1;
            ENVC += 1;
        }
    }

    // If no argv was provided, use path as argv[0]
    if ARGC == 0 {
        let len = path.len().min(255);
        ARGV_OFFSETS[0] = 0;
        ARGV_LENS[0] = len;
        for i in 0..len { ARGV_BUF[i] = path[i]; }
        ARGV_BUF[len] = 0;
        ARGC = 1;
    }
}

/// Simple set with path and optional single argument (for kernel boot).
pub fn set(path: &[u8], arg: &[u8]) {
    unsafe {
        ARGC = 0;
        ENVC = 0; // boot path uses default env

        // argv[0] = path
        let plen = path.len().min(255);
        ARGV_OFFSETS[0] = 0;
        ARGV_LENS[0] = plen;
        for i in 0..plen { ARGV_BUF[i] = path[i]; }
        ARGV_BUF[plen] = 0;
        let buf_pos = plen + 1;
        ARGC = 1;

        // argv[1] = arg (if non-empty)
        if !arg.is_empty() {
            let alen = arg.len().min(255);
            ARGV_OFFSETS[1] = buf_pos;
            ARGV_LENS[1] = alen;
            for i in 0..alen { ARGV_BUF[buf_pos + i] = arg[i]; }
            ARGV_BUF[buf_pos + alen] = 0;
            ARGC = 2;
        }
    }
}

/// Write Linux-compatible stack layout for the new process.
///
/// Layout: [sp]=argc, argv[0..n], NULL, envp[0..m], NULL, auxv, strings
/// Default environment for boot/init (when no user envp provided).
const DEFAULT_ENV: [&[u8]; 5] = [
    b"PATH=/bin:/sbin:/usr/bin:/usr/sbin\0",
    b"HOME=/root\0",
    b"TERM=linux\0",
    b"LANG=C.UTF-8\0",
    b"PYTHONUTF8=1\0",
];

pub unsafe fn write_to_stack(stack_top: usize) -> usize {
    let argc = ARGC;
    let envc = ENVC.min(MAX_ARGS);
    let use_user_env = envc > 0;
    let env_count = if use_user_env { envc } else { DEFAULT_ENV.len() };

    // Calculate string area size
    let mut str_size = 0usize;
    for i in 0..argc.min(MAX_ARGS) {
        str_size = str_size.saturating_add(ARGV_LENS[i].min(256).saturating_add(1));
    }
    if use_user_env {
        for i in 0..envc {
            str_size = str_size.saturating_add(ENVP_LENS[i].min(256).saturating_add(1));
        }
    } else {
        for env in &DEFAULT_ENV { str_size += env.len(); }
    }

    let word = core::mem::size_of::<usize>();
    let dyn_auxv_count = if AUXV_PHDR != 0 { 5 } else { 0 };
    let auxv_size = (8 + dyn_auxv_count) * 2 * word;
    let random_size = 16;

    let header_slots = 1 + argc + 1 + env_count + 1;
    let header_size = header_slots * word;

    let total = header_size + auxv_size + random_size + str_size;
    let aligned_total = (total + 15) & !15;

    let sp = stack_top - aligned_total;
    let random_base = sp + header_size + auxv_size;
    let str_base = random_base + random_size;

    // Write 16 pseudorandom bytes for AT_RANDOM (stack canary seed).
    // No entropy source available — use a simple mix of stack address + counter.
    // musl just needs non-zero bytes; cryptographic quality not required.
    {
        static mut RAND_COUNTER: u64 = 0x517e_4d6f_7275_7321; // "SqMorus!"
        RAND_COUNTER = RAND_COUNTER.wrapping_mul(6364136223846793005).wrapping_add(1);
        let r = random_base as *mut u64;
        *r = RAND_COUNTER ^ (stack_top as u64);
        RAND_COUNTER = RAND_COUNTER.wrapping_mul(6364136223846793005).wrapping_add(1);
        *r.add(1) = RAND_COUNTER ^ (sp as u64);
    }

    // Write strings
    let mut str_pos = str_base;
    let mut argv_addrs = [0usize; MAX_ARGS];

    for i in 0..argc {
        argv_addrs[i] = str_pos;
        let p = str_pos as *mut u8;
        let len = ARGV_LENS[i];
        let off = ARGV_OFFSETS[i];
        for j in 0..len { *p.add(j) = ARGV_BUF[off + j]; }
        *p.add(len) = 0;
        str_pos += len + 1;
    }

    let mut env_addrs = [0usize; MAX_ARGS];
    if use_user_env {
        for i in 0..envc {
            env_addrs[i] = str_pos;
            let p = str_pos as *mut u8;
            let len = ENVP_LENS[i];
            let off = ENVP_OFFSETS[i];
            for j in 0..len { *p.add(j) = ENVP_BUF[off + j]; }
            *p.add(len) = 0;
            str_pos += len + 1;
        }
    } else {
        for (idx, env) in DEFAULT_ENV.iter().enumerate() {
            env_addrs[idx] = str_pos;
            let p = str_pos as *mut u8;
            for (j, &b) in env.iter().enumerate() { *p.add(j) = b; }
            str_pos += env.len();
        }
    }

    // Write header (pointer-width slots)
    let hdr = sp as *mut usize;
    let mut slot = 0;

    *hdr.add(slot) = argc; slot += 1;
    for i in 0..argc {
        *hdr.add(slot) = argv_addrs[i]; slot += 1;
    }
    *hdr.add(slot) = 0; slot += 1; // argv NULL

    for i in 0..env_count {
        *hdr.add(slot) = env_addrs[i]; slot += 1;
    }
    *hdr.add(slot) = 0; slot += 1; // envp NULL

    // Auxiliary vector (pointer-width pairs)
    let auxv = hdr.add(slot) as *mut [usize; 2];
    let mut ai = 0;
    (*auxv.add(ai)) = [6, 4096];            ai += 1; // AT_PAGESZ
    (*auxv.add(ai)) = [11, 0];              ai += 1; // AT_UID
    (*auxv.add(ai)) = [12, 0];              ai += 1; // AT_EUID (was 23=AT_SECURE)
    (*auxv.add(ai)) = [13, 0];              ai += 1; // AT_GID
    (*auxv.add(ai)) = [14, 0];              ai += 1; // AT_EGID
    // AT_HWCAP: advertise FP+ASIMD (mandatory on ARMv8), plus common features.
    // Without these, musl/libc may use slow fallback paths.
    #[cfg(target_arch = "aarch64")]
    { (*auxv.add(ai)) = [16, 0xFF]; ai += 1; } // FP|ASIMD|EVTSTRM|AES|PMULL|SHA1|SHA2|CRC32
    #[cfg(not(target_arch = "aarch64"))]
    { (*auxv.add(ai)) = [16, 0];   ai += 1; } // AT_HWCAP
    (*auxv.add(ai)) = [25, random_base];    ai += 1; // AT_RANDOM (16 random bytes)

    // Dynamic linking entries (only if set)
    if AUXV_PHDR != 0 {
        (*auxv.add(ai)) = [3, AUXV_PHDR];   ai += 1; // AT_PHDR
        (*auxv.add(ai)) = [4, AUXV_PHENT];  ai += 1; // AT_PHENT
        (*auxv.add(ai)) = [5, AUXV_PHNUM];  ai += 1; // AT_PHNUM
        (*auxv.add(ai)) = [9, AUXV_ENTRY];  ai += 1; // AT_ENTRY
        (*auxv.add(ai)) = [7, AUXV_BASE];   ai += 1; // AT_BASE
    }

    (*auxv.add(ai)) = [0, 0]; // AT_NULL

    // Build cmdline: null-separated argv for /proc/[pid]/cmdline
    let mut cpos = 0u8;
    for i in 0..argc {
        let len = ARGV_LENS[i].min(127 - cpos as usize);
        let off = ARGV_OFFSETS[i];
        for j in 0..len {
            CMDLINE_BUF[cpos as usize + j] = ARGV_BUF[off + j];
        }
        cpos += len as u8;
        if (cpos as usize) < 127 { CMDLINE_BUF[cpos as usize] = 0; cpos += 1; }
    }
    CMDLINE_LEN = cpos;

    sp
}
