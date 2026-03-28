/// Kernel buffer for passing exec arguments to the new process.
/// Writes a Linux-compatible stack layout (argc, argv, envp, auxv).

const MAX_ARG: usize = 256;

static mut EXEC_PATH: [u8; MAX_ARG] = [0; MAX_ARG];
static mut EXEC_ARG: [u8; MAX_ARG] = [0; MAX_ARG];
static mut PATH_LEN: usize = 0;
static mut ARG_LEN: usize = 0;

/// Store the exec path and optional argument.
pub fn set(path: &[u8], arg: &[u8]) {
    unsafe {
        let plen = path.len().min(MAX_ARG - 1);
        EXEC_PATH[..plen].copy_from_slice(&path[..plen]);
        EXEC_PATH[plen] = 0;
        PATH_LEN = plen;

        let alen = arg.len().min(MAX_ARG - 1);
        EXEC_ARG[..alen].copy_from_slice(&arg[..alen]);
        EXEC_ARG[alen] = 0;
        ARG_LEN = alen;
    }
}

/// Write a Linux-compatible stack layout for the new process.
///
/// Layout (from low address / SP upward):
/// ```
/// [sp+0]   = argc
/// [sp+8]   = argv[0] pointer
/// [sp+16]  = argv[1] pointer (if arg present)
///            NULL               (argv terminator)
///            envp[0] pointer    ("PATH=...")
///            NULL               (envp terminator)
///            AT_PAGESZ(6), 4096
///            AT_UID(11), 0
///            AT_EUID(23), 0
///            AT_GID(13), 0
///            AT_EGID(14), 0
///            AT_NULL(0), 0      (auxv terminator)
///            string data...
/// ```
pub unsafe fn write_to_stack(stack_top: u64) -> u64 {
    let path_len = PATH_LEN;
    let arg_len = ARG_LEN;
    let argc = if arg_len > 0 { 2usize } else { 1usize };

    // Environment strings
    let env_str = b"PATH=/bin:/sbin:/usr/bin:/usr/sbin\0";
    let home_str = b"HOME=/root\0";
    let term_str = b"TERM=linux\0";

    // Calculate string area size
    let str_size = (path_len + 1)
        + (if arg_len > 0 { arg_len + 1 } else { 0 })
        + env_str.len() + home_str.len() + term_str.len();

    // Auxv: 5 pairs + AT_NULL = 6 pairs × 16 bytes = 96 bytes
    let auxv_size = 6 * 16;

    // Header: argc + argv[0..argc] + NULL + envp[0..3] + NULL
    let header_slots = 1 + argc + 1 + 3 + 1; // argc, argv ptrs, null, envp ptrs, null
    let header_size = header_slots * 8;

    let total = header_size + auxv_size + str_size;
    let aligned_total = (total + 15) & !15;

    let sp = stack_top - aligned_total as u64;

    // String area starts after header + auxv
    let str_base = sp + (header_size + auxv_size) as u64;

    // Write strings
    let mut str_pos = str_base;

    // argv[0] string
    let argv0_addr = str_pos;
    let p = str_pos as *mut u8;
    for i in 0..path_len { *p.add(i) = EXEC_PATH[i]; }
    *p.add(path_len) = 0;
    str_pos += (path_len + 1) as u64;

    // argv[1] string (if present)
    let argv1_addr = if arg_len > 0 {
        let addr = str_pos;
        let p = str_pos as *mut u8;
        for i in 0..arg_len { *p.add(i) = EXEC_ARG[i]; }
        *p.add(arg_len) = 0;
        str_pos += (arg_len + 1) as u64;
        addr
    } else {
        0
    };

    // envp[0] string
    let env0_addr = str_pos;
    let p = str_pos as *mut u8;
    for (i, &b) in env_str.iter().enumerate() { *p.add(i) = b; }
    str_pos += env_str.len() as u64;

    let env1_addr = str_pos;
    let p = str_pos as *mut u8;
    for (i, &b) in home_str.iter().enumerate() { *p.add(i) = b; }
    str_pos += home_str.len() as u64;

    let env2_addr = str_pos;
    let p = str_pos as *mut u8;
    for (i, &b) in term_str.iter().enumerate() { *p.add(i) = b; }

    // Write header
    let hdr = sp as *mut u64;
    let mut slot = 0;

    // argc
    *hdr.add(slot) = argc as u64; slot += 1;

    // argv pointers
    *hdr.add(slot) = argv0_addr; slot += 1;
    if arg_len > 0 {
        *hdr.add(slot) = argv1_addr; slot += 1;
    }
    *hdr.add(slot) = 0; slot += 1; // argv NULL terminator

    // envp pointers
    *hdr.add(slot) = env0_addr; slot += 1;
    *hdr.add(slot) = env1_addr; slot += 1;
    *hdr.add(slot) = env2_addr; slot += 1;
    *hdr.add(slot) = 0; slot += 1; // envp NULL terminator

    // Auxiliary vector (pairs of u64: type, value)
    let auxv = hdr.add(slot) as *mut [u64; 2];
    (*auxv.add(0)) = [6, 4096];       // AT_PAGESZ = 4096
    (*auxv.add(1)) = [11, 0];         // AT_UID = 0
    (*auxv.add(2)) = [23, 0];         // AT_EUID = 0
    (*auxv.add(3)) = [13, 0];         // AT_GID = 0
    (*auxv.add(4)) = [14, 0];         // AT_EGID = 0
    (*auxv.add(5)) = [0, 0];          // AT_NULL (terminator)

    sp
}
