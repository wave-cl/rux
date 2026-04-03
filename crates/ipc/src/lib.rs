//! Inter-process communication primitives.
//!
//! Provides pipe ring buffers for kernel IPC. The buffer management
//! is generic — fd allocation is handled by rux_fs::fdtable.

#![cfg_attr(not(test), no_std)]

pub mod pipe;

/// Pre-built PipeFns that maps directly to this crate's pipe functions.
/// No wrappers, no traits — just function pointers.
pub static PIPE_FNS: rux_fs::fdtable::PipeFns = rux_fs::fdtable::PipeFns {
    read: pipe::read,
    write: pipe::write,
    close: pipe::close,
    dup_ref: pipe::dup_ref,
    alloc: pipe::alloc,
};
