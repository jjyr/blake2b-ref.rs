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
