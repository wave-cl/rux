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

/// Read argv from user memory (pointer to NULL-terminated array of char*).
/// If argv_ptr is NULL or 0, uses path as argv[0].
pub unsafe fn set_from_user(path: &[u8], argv_ptr: usize, _envp_ptr: usize) {
    ARGC = 0;
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
        let mut buf_pos = 0usize;

        // argv[0] = path
        let plen = path.len().min(255);
        ARGV_OFFSETS[0] = 0;
        ARGV_LENS[0] = plen;
        for i in 0..plen { ARGV_BUF[i] = path[i]; }
        ARGV_BUF[plen] = 0;
        buf_pos = plen + 1;
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
pub unsafe fn write_to_stack(stack_top: usize) -> usize {
    let argc = ARGC;

    // Environment strings
    // Note: ENV=/etc/profile causes ash to crash during early init.
    // Tests run via `. /etc/profile` fed through stdin instead.
    let env_strs: [&[u8]; 3] = [
        b"PATH=/bin:/sbin:/usr/bin:/usr/sbin\0",
        b"HOME=/root\0",
        b"TERM=linux\0",
    ];

    // Calculate string area size
    let mut str_size = 0usize;
    for i in 0..argc {
        str_size += ARGV_LENS[i] + 1;
    }
    for env in &env_strs {
        str_size += env.len();
    }

    let word = core::mem::size_of::<usize>(); // 8 on 64-bit, 4 on 32-bit

    // Auxv: 6 pairs × 2 words each
    let auxv_size = 6 * 2 * word;

    // Header: argc + argv[0..argc] + NULL + envp[0..3] + NULL
    let header_slots = 1 + argc + 1 + env_strs.len() + 1;
    let header_size = header_slots * word;

    let total = header_size + auxv_size + str_size;
    let aligned_total = (total + 15) & !15;

    let sp = stack_top - aligned_total;
    let str_base = sp + header_size + auxv_size;

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

    let mut env_addrs = [0usize; 8];
    for (idx, env) in env_strs.iter().enumerate() {
        env_addrs[idx] = str_pos;
        let p = str_pos as *mut u8;
        for (j, &b) in env.iter().enumerate() { *p.add(j) = b; }
        str_pos += env.len();
    }

    // Write header (pointer-width slots)
    let hdr = sp as *mut usize;
    let mut slot = 0;

    *hdr.add(slot) = argc; slot += 1;
    for i in 0..argc {
        *hdr.add(slot) = argv_addrs[i]; slot += 1;
    }
    *hdr.add(slot) = 0; slot += 1; // argv NULL

    for i in 0..env_strs.len() {
        *hdr.add(slot) = env_addrs[i]; slot += 1;
    }
    *hdr.add(slot) = 0; slot += 1; // envp NULL

    // Auxiliary vector (pointer-width pairs)
    let auxv = hdr.add(slot) as *mut [usize; 2];
    (*auxv.add(0)) = [6, 4096];   // AT_PAGESZ
    (*auxv.add(1)) = [11, 0];     // AT_UID
    (*auxv.add(2)) = [23, 0];     // AT_EUID
    (*auxv.add(3)) = [13, 0];     // AT_GID
    (*auxv.add(4)) = [14, 0];     // AT_EGID
    (*auxv.add(5)) = [0, 0];      // AT_NULL

    sp
}
