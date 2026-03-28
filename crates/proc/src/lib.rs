#![no_std]

pub type Pid = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProcessState {
    Created,
    Running,
    Stopped,
    Zombie,
    Dead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Signal {
    Hangup = 1,
    Interrupt = 2,
    Quit = 3,
    Illegal = 4,
    Trap = 5,
    Abort = 6,
    Bus = 7,
    FloatingPoint = 8,
    Kill = 9,
    User1 = 10,
    Segfault = 11,
    User2 = 12,
    Pipe = 13,
    Alarm = 14,
    Terminate = 15,
    Child = 17,
    Continue = 18,
    Stop = 19,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Code(i32),
    Signaled(Signal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProcError {
    NotFound,
    PermissionDenied,
    ResourceLimit,
    InvalidSignal,
    ZombieProcess,
}
