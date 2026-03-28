#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KernelError {
    OutOfMemory,
    InvalidAddress,
    PermissionDenied,
    NotFound,
    AlreadyExists,
    InvalidArgument,
    ResourceBusy,
    NotSupported,
    IoError,
    Timeout,
}
