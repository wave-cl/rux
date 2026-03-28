#![no_std]

use rux_klib::PhysAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MemoryRegionType {
    Usable,
    Reserved,
    AcpiReclaimable,
    AcpiNvs,
    Defective,
    BootloaderReclaimable,
    KernelAndModules,
    Framebuffer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PixelFormat {
    Rgb,
    Bgr,
    Bitmask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootError {
    InvalidMemoryMap,
    NoFramebuffer,
    InvalidCommandLine,
    AcpiNotFound,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryRegion {
    pub start: PhysAddr,        // 0  (u64 via transparent)
    pub size: usize,            // 8
    pub kind: MemoryRegionType, // 16 (u8, repr(u8))
    pub _pad: [u8; 7],          // 17–23 — 24 bytes, natural alignment
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FramebufferInfo {
    pub addr: PhysAddr,         // 0  (u64)
    pub width: u32,             // 8
    pub height: u32,            // 12
    pub stride: u32,            // 16
    pub bpp: u8,                // 20
    pub pixel_format: PixelFormat, // 21 (u8, repr(u8))
    pub _pad: [u8; 2],          // 22–23 — 24 bytes total
}

// ── Compile-time layout assertions ──────────────────────────────────────
const _: () = {
    assert!(core::mem::size_of::<MemoryRegion>() == 24);
    assert!(core::mem::size_of::<FramebufferInfo>() == 24);
};

pub struct BootInfo<'a> {
    pub memory_regions: &'a [MemoryRegion],
    pub framebuffer: Option<FramebufferInfo>,
    pub command_line: Option<&'a str>,
    pub rsdp_addr: Option<PhysAddr>,
}
