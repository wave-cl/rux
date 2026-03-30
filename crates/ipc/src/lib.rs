//! Inter-process communication primitives.
//!
//! Provides pipe ring buffers for kernel IPC. The buffer management
//! is generic — fd allocation is handled by rux_vfs::fdtable.

#![no_std]

pub mod pipe;

/// Pre-built PipeFns that maps directly to this crate's pipe functions.
/// No wrappers, no traits — just function pointers.
pub static PIPE_FNS: rux_vfs::fdtable::PipeFns = rux_vfs::fdtable::PipeFns {
    read: pipe::read,
    write: pipe::write,
    close: pipe::close,
    dup_ref: pipe::dup_ref,
    alloc: pipe::alloc,
};
