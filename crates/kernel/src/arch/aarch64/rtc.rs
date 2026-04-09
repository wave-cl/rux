/// PL031 RTC — reads wall-clock time at boot.
///
/// QEMU's `virt` machine places a PL031 RTC at MMIO address 0x0901_0000.
/// Register at offset 0 (RTCDR) returns seconds since Unix epoch.

const PL031_BASE: usize = 0x0901_0000;

/// Read the PL031 RTC data register (seconds since epoch).
pub unsafe fn read_rtc() -> u64 {
    let dr = PL031_BASE as *const u32;
    core::ptr::read_volatile(dr) as u64
}
