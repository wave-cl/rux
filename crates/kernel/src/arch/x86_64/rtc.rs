/// CMOS RTC (MC146818) — reads wall-clock time at boot.
///
/// QEMU always emulates this at I/O ports 0x70/0x71.
/// We read the time once at boot to set the CLOCK_REALTIME epoch.

const CMOS_ADDR: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nostack, preserves_flags));
    val
}

unsafe fn read_cmos(reg: u8) -> u8 {
    outb(CMOS_ADDR, reg);
    inb(CMOS_DATA)
}

fn bcd_to_bin(bcd: u8) -> u8 {
    (bcd & 0x0F) + (bcd >> 4) * 10
}

/// Read the CMOS RTC and return seconds since Unix epoch.
pub unsafe fn read_rtc() -> u64 {
    // Wait for "update not in progress" (reg 0x0A bit 7)
    for _ in 0..10000 {
        if read_cmos(0x0A) & 0x80 == 0 { break; }
    }

    let mut sec = read_cmos(0x00);
    let mut min = read_cmos(0x02);
    let mut hour = read_cmos(0x04);
    let mut day = read_cmos(0x07);
    let mut month = read_cmos(0x08);
    let mut year = read_cmos(0x09);
    let century = read_cmos(0x32); // ACPI century register

    let status_b = read_cmos(0x0B);
    let is_bcd = status_b & 0x04 == 0; // bit 2 clear = BCD mode

    if is_bcd {
        sec = bcd_to_bin(sec);
        min = bcd_to_bin(min);
        hour = bcd_to_bin(hour);
        day = bcd_to_bin(day);
        month = bcd_to_bin(month);
        year = bcd_to_bin(year);
    }

    let full_year = if century > 0 {
        (if is_bcd { bcd_to_bin(century) } else { century }) as u32 * 100 + year as u32
    } else {
        // Assume 2000s if no century register
        2000 + year as u32
    };

    ymdhms_to_epoch(full_year, month as u32, day as u32, hour as u32, min as u32, sec as u32)
}

/// Convert date/time to Unix timestamp (seconds since 1970-01-01 00:00:00 UTC).
fn ymdhms_to_epoch(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> u64 {
    // Days from 1970-01-01 to start of year
    let mut days = 0u64;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    // Days from start of year to start of month
    let mdays: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += mdays[(m - 1) as usize] as u64;
        if m == 2 && is_leap(year) { days += 1; }
    }
    days += (day - 1) as u64;
    days * 86400 + hour as u64 * 3600 + min as u64 * 60 + sec as u64
}

fn is_leap(y: u32) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}
