#![cfg_attr(not(test), no_std)]

mod libc;
mod blake2b_ref;
#[cfg(test)]
mod tests;

trait Fill {
    fn fill(&mut self, num: u8, size: usize);
}

impl Fill for [u8] {
    fn fill(&mut self, num: u8, size: usize) {
        for i in &mut self[..size] {
            *i = num;
        }
    }
}
