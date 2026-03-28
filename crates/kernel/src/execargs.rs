/// Kernel buffer for passing exec arguments from shell to child process.
/// Since rux runs one process at a time (vfork), a single global buffer works.

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

/// Write argc, argv pointers, and string data onto the user stack.
/// Returns the adjusted stack pointer (aligned to 16 bytes).
///
/// Stack layout (growing down):
///   [sp+0]  = argc (1 or 2)
///   [sp+8]  = argv[0] pointer (to path string below)
///   [sp+16] = argv[1] pointer (to arg string, or 0)
///   [sp+24] = path string (null-terminated)
///   [sp+24+pathlen+1] = arg string (null-terminated, if present)
pub unsafe fn write_to_stack(stack_top: u64) -> u64 {
    let path_len = PATH_LEN;
    let arg_len = ARG_LEN;

    // Calculate space needed for strings
    let strings_size = (path_len + 1) + if arg_len > 0 { arg_len + 1 } else { 0 };
    // Header: argc + argv[0] + argv[1] = 24 bytes
    let header_size = 24usize;
    let total = header_size + strings_size;
    // Align to 16 bytes
    let aligned_total = (total + 15) & !15;

    let sp = stack_top - aligned_total as u64;
    let base = sp as *mut u8;

    // Write strings after the header
    let path_addr = sp + header_size as u64;
    let path_ptr = path_addr as *mut u8;
    for i in 0..path_len {
        *path_ptr.add(i) = EXEC_PATH[i];
    }
    *path_ptr.add(path_len) = 0;

    let (argc, arg_ptr_val) = if arg_len > 0 {
        let arg_addr = path_addr + (path_len as u64 + 1);
        let arg_ptr = arg_addr as *mut u8;
        for i in 0..arg_len {
            *arg_ptr.add(i) = EXEC_ARG[i];
        }
        *arg_ptr.add(arg_len) = 0;
        (2u64, arg_addr)
    } else {
        (1u64, 0u64)
    };

    // Write header
    let hdr = base as *mut u64;
    *hdr.add(0) = argc;
    *hdr.add(1) = path_addr;
    *hdr.add(2) = arg_ptr_val;

    sp
}
