#![allow(non_camel_case_types)]
#![allow(dead_code)]
/// Dummy libc
pub use core::ffi::c_void;
pub type c_int = i32;
pub type c_uint = u32;
pub type c_char = i8;
pub type c_uchar = u8;
pub type c_ulong = u64;
pub type c_ulonglong = u64;
