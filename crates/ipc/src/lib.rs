//! Inter-process communication primitives.
//!
//! Provides pipe ring buffers for kernel IPC. The buffer management
//! is generic — fd allocation is handled by the kernel.

#![no_std]

pub mod pipe;

/// Zero-sized type that implements PipeOps and PipeAllocator
/// by mapping directly to the pipe module functions.
pub struct IpcPipe;

impl rux_vfs::fdtable::PipeOps for IpcPipe {
    fn pipe_read(&self, pipe_id: u8, buf: *mut u8, len: usize) -> isize {
        pipe::read(pipe_id, buf, len)
    }
    fn pipe_write(&self, pipe_id: u8, buf: *const u8, len: usize) -> isize {
        pipe::write(pipe_id, buf, len)
    }
    fn pipe_close(&self, pipe_id: u8, is_write_end: bool) {
        pipe::close(pipe_id, is_write_end);
    }
    fn pipe_dup_ref(&self, pipe_id: u8, is_write_end: bool) {
        pipe::dup_ref(pipe_id, is_write_end);
    }
}

impl rux_vfs::fdtable::PipeAllocator for IpcPipe {
    fn alloc(&self) -> Result<u8, isize> {
        pipe::alloc()
    }
    fn close(&self, pipe_id: u8, is_write_end: bool) {
        pipe::close(pipe_id, is_write_end);
    }
}
