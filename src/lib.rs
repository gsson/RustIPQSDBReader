// Copyright 2023 IPQualityScore LLC
//! # IPQualityScore Flat File Database Reader
//!
//! The ipqs_db_reader library crate allows IPQualityScore customers to easily integrate our IP
//! reputation flat file database with your Rust code.
//!
//! For an overview of the flat file database features and to get started with your own
//! file, please see our
//! [Flat File IP Address Database Documentation Overview](https://www.ipqualityscore.com/documentation/ip-reputation-database/overview).

pub mod file_reader;
pub mod memory_reader;
pub use file_reader::record::{Record, Strictness};
pub use file_reader::FileReader;
pub use memory_reader::MemoryReader;

mod binary_option;
mod column;
mod parse;
mod variable_length_int;

mod utility {
    // interpret an array of four bytes as a Little Endian unsigned integer
    pub(crate) fn four_byte_int(bytes: &[u8]) -> u64 {
        let mut buffer = [0u8; 4];
        buffer[..4].copy_from_slice(bytes);

        u32::from_le_bytes(buffer) as u64
    }
    // interpret an array of four bytes as a 32-bit floating-point number
    pub(crate) fn four_byte_float(bytes: &[u8]) -> f32 {
        let mut buffer = [0u8; 4];
        buffer[..4].copy_from_slice(bytes);

        f32::from_le_bytes(buffer)
    }

    pub(crate) fn parse_string(data: &[u8]) -> Result<&str, Box<dyn std::error::Error>> {
        let size = usize::from(data[0]);
        let value = std::str::from_utf8(&data[1..1 + size])?;
        Ok(value)
    }
}
