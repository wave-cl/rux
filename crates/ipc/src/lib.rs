//! Inter-process communication primitives.
//!
//! Provides pipe ring buffers for kernel IPC. The buffer management
//! is generic — fd allocation is handled by the kernel.

#![no_std]

pub mod pipe;
