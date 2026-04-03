//! Minimal PCI configuration space access via x86 port I/O.
//!
//! Scans bus 0 for devices. Used at boot time to find virtio-pci devices.
//! No MSI/MSI-X, no interrupt routing — polling only.

/// PCI config address port (write bus/dev/fn/reg).
const PCI_CONFIG_ADDR: u16 = 0xCF8;
/// PCI config data port (read/write 32-bit value).
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// A PCI device location (bus/device/function).
#[derive(Clone, Copy)]
pub struct PciAddr {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
}

/// A discovered PCI device.
#[derive(Clone, Copy)]
pub struct PciDevice {
    pub addr: PciAddr,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub bar0: u32,
    pub bar1: u32,
    /// Offset of the PCI capabilities list (0 if none).
    pub cap_ptr: u8,
}

impl PciAddr {
    /// Build a CONFIG_ADDRESS value for a given register offset.
    fn config_addr(self, reg: u8) -> u32 {
        0x8000_0000
            | ((self.bus as u32) << 16)
            | ((self.dev as u32) << 11)
            | ((self.func as u32) << 8)
            | ((reg as u32) & 0xFC)
    }
}

/// Read a 32-bit PCI config register.
///
/// # Safety
/// x86 port I/O.
pub unsafe fn pci_read32(addr: PciAddr, reg: u8) -> u32 {
    let val = addr.config_addr(reg);
    core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") val, options(nostack));
    let data: u32;
    core::arch::asm!("in eax, dx", out("eax") data, in("dx") PCI_CONFIG_DATA, options(nostack));
    data
}

/// Write a 32-bit PCI config register.
///
/// # Safety
/// x86 port I/O.
pub unsafe fn pci_write32(addr: PciAddr, reg: u8, val: u32) {
    let a = addr.config_addr(reg);
    core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") a, options(nostack));
    core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_DATA, in("eax") val, options(nostack));
}

/// Read a 16-bit PCI config register.
pub unsafe fn pci_read16(addr: PciAddr, reg: u8) -> u16 {
    let dword = pci_read32(addr, reg & 0xFC);
    let shift = ((reg & 2) as u32) * 8;
    (dword >> shift) as u16
}

/// Read an 8-bit PCI config register.
pub unsafe fn pci_read8(addr: PciAddr, reg: u8) -> u8 {
    let dword = pci_read32(addr, reg & 0xFC);
    let shift = ((reg & 3) as u32) * 8;
    (dword >> shift) as u8
}

/// Scan PCI bus 0 for all devices. Calls `f` for each found device.
pub unsafe fn scan_bus<F: FnMut(PciDevice)>(mut f: F) {
    for dev in 0..32u8 {
        let addr = PciAddr { bus: 0, dev, func: 0 };
        let id = pci_read32(addr, 0x00);
        if id == 0xFFFF_FFFF { continue; } // no device

        let vendor_id = id as u16;
        let device_id = (id >> 16) as u16;
        let class_rev = pci_read32(addr, 0x08);
        let class = (class_rev >> 24) as u8;
        let subclass = (class_rev >> 16) as u8;
        let bar0 = pci_read32(addr, 0x10);
        let bar1 = pci_read32(addr, 0x14);
        let cap_ptr = pci_read8(addr, 0x34);

        f(PciDevice { addr, vendor_id, device_id, class, subclass, bar0, bar1, cap_ptr });
    }
}

/// Find the first PCI device matching a vendor/device ID pair.
pub unsafe fn find_device(vendor: u16, device: u16) -> Option<PciDevice> {
    let mut found: Option<PciDevice> = None;
    scan_bus(|d| {
        if found.is_none() && d.vendor_id == vendor && d.device_id == device {
            found = Some(d);
        }
    });
    found
}

// ── virtio PCI constants ───────────────────────────────────────────

/// Red Hat virtio vendor ID.
pub const VIRTIO_VENDOR: u16 = 0x1AF4;
/// virtio-blk transitional device ID (legacy).
pub const VIRTIO_BLK_LEGACY: u16 = 0x1001;
/// virtio-blk modern device ID.
pub const VIRTIO_BLK_MODERN: u16 = 0x1042;

/// Enable PCI bus mastering for a device (required for DMA).
pub unsafe fn enable_bus_master(addr: PciAddr) {
    let cmd = pci_read16(addr, 0x04);
    let new_cmd = cmd | 0x06; // bus master + memory space enable
    pci_write32(addr, 0x04, (pci_read32(addr, 0x04) & 0xFFFF_0000) | new_cmd as u32);
}
