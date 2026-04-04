//! Kernel command line parser.
//!
//! Parses boot parameters like `root=/dev/vda init=/sbin/init rootfstype=ext2`.
//! No heap allocation — uses static buffers and byte scanning.

/// Parsed kernel command line parameters.
pub struct CmdlineParams {
    /// Root device path (e.g., "/dev/vda"), empty if not specified.
    pub root: [u8; 64],
    pub root_len: usize,
    /// Init program path (e.g., "/sbin/init"), empty if not specified.
    pub init: [u8; 64],
    pub init_len: usize,
    /// Root filesystem type (e.g., "ext2"), empty if not specified.
    pub rootfstype: [u8; 16],
    pub rootfstype_len: usize,
}

impl CmdlineParams {
    pub const fn empty() -> Self {
        Self {
            root: [0; 64], root_len: 0,
            init: [0; 64], init_len: 0,
            rootfstype: [0; 16], rootfstype_len: 0,
        }
    }

    #[allow(dead_code)]
    pub fn has_root(&self) -> bool { self.root_len > 0 }
}

/// Parse a null-terminated or length-bounded command line string.
pub fn parse(cmdline: &[u8]) -> CmdlineParams {
    let mut params = CmdlineParams::empty();

    // Iterate space-separated tokens
    let mut i = 0;
    let len = cmdline.len();
    while i < len {
        // Skip whitespace
        while i < len && (cmdline[i] == b' ' || cmdline[i] == b'\0') { i += 1; }
        if i >= len { break; }

        // Find end of token
        let start = i;
        while i < len && cmdline[i] != b' ' && cmdline[i] != b'\0' { i += 1; }
        let token = &cmdline[start..i];

        // Match known parameters
        if let Some(val) = strip_prefix(token, b"root=") {
            let n = val.len().min(63);
            params.root[..n].copy_from_slice(&val[..n]);
            params.root_len = n;
        } else if let Some(val) = strip_prefix(token, b"init=") {
            let n = val.len().min(63);
            params.init[..n].copy_from_slice(&val[..n]);
            params.init_len = n;
        } else if let Some(val) = strip_prefix(token, b"rootfstype=") {
            let n = val.len().min(15);
            params.rootfstype[..n].copy_from_slice(&val[..n]);
            params.rootfstype_len = n;
        }
    }

    params
}

fn strip_prefix<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if s.len() >= prefix.len() && &s[..prefix.len()] == prefix {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}
