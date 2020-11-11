# blake2b-ref.rs
[![Crates.io](https://img.shields.io/crates/v/blake2b-ref.svg)](https://crates.io/crates/blake2b-ref)

A `no_std` BLAKE2B crate.

This crate is transcompiled by [c2rust]; the source code is from the offcial [BLAKE2] ref implementation.
The transcompiled source has been modified slightly to support `no_std`.

The API design is highly inspired - almost copy from https://github.com/nervosnetwork/blake2b-rs.


[c2rust]: https://github.com/immunant/c2rust "c2rust"
[BLAKE2]: https://github.com/BLAKE2/BLAKE2 "BLAKE2"
