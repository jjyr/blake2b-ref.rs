//! This crate is transcompiled from blake2b-ref
//!
//! # Example:
//!
//! ```
//! use blake2b_ref::Blake2bBuilder;
//!
//! fn hash_message(msg: &[u8]) -> [u8; 32] {
//!     let mut output = [0u8; 32];
//!     let mut blake2b = Blake2bBuilder::new(32).personal(b"SMT").build();
//!     blake2b.update(msg);
//!     blake2b.finalize(&mut output);
//!     output
//! }
//! ```

#![cfg_attr(not(test), no_std)]

mod blake2b_ref;
mod libc;
#[cfg(test)]
mod tests;
mod wrapper;

pub use crate::wrapper::{blake2b, Blake2b, Blake2bBuilder};

trait Fill {
    fn fill_bytes(&mut self, num: u8, size: usize);
}

impl Fill for [u8] {
    fn fill_bytes(&mut self, num: u8, size: usize) {
        for i in &mut self[..size] {
            *i = num;
        }
    }
}
