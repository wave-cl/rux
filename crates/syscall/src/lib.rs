#![no_std]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Syscall {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Stat = 4,
    Fstat = 5,
    Lseek = 8,
    Mmap = 9,
    Mprotect = 10,
    Munmap = 11,
    Brk = 12,
    Ioctl = 16,
    Pipe = 22,
    Dup = 32,
    Dup2 = 33,
    Fork = 57,
    Exec = 59,
    Exit = 60,
    Wait = 61,
    Kill = 62,
    Getpid = 39,
    Socket = 41,
    Bind = 49,
    Listen = 50,
    Accept = 43,
    Connect = 42,
    Send = 44,
    Recv = 45,
    Yield = 24,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SyscallError {
    InvalidNumber,
    BadAddress,
    Fault,
    InvalidArgument,
    PermissionDenied,
    Interrupted,
}

impl Syscall {
    #[inline(always)]
    pub fn from_number(nr: usize) -> Result<Self, SyscallError> {
        match nr {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            2 => Ok(Self::Open),
            3 => Ok(Self::Close),
            4 => Ok(Self::Stat),
            5 => Ok(Self::Fstat),
            8 => Ok(Self::Lseek),
            9 => Ok(Self::Mmap),
            10 => Ok(Self::Mprotect),
            11 => Ok(Self::Munmap),
            12 => Ok(Self::Brk),
            16 => Ok(Self::Ioctl),
            22 => Ok(Self::Pipe),
            24 => Ok(Self::Yield),
            32 => Ok(Self::Dup),
            33 => Ok(Self::Dup2),
            39 => Ok(Self::Getpid),
            41 => Ok(Self::Socket),
            42 => Ok(Self::Connect),
            43 => Ok(Self::Accept),
            44 => Ok(Self::Send),
            45 => Ok(Self::Recv),
            49 => Ok(Self::Bind),
            50 => Ok(Self::Listen),
            57 => Ok(Self::Fork),
            59 => Ok(Self::Exec),
            60 => Ok(Self::Exit),
            61 => Ok(Self::Wait),
            62 => Ok(Self::Kill),
            _ => Self::unknown_syscall(),
        }
    }

    #[cold]
    fn unknown_syscall() -> Result<Self, SyscallError> {
        Err(SyscallError::InvalidNumber)
    }
}
