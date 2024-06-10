use std::error::Error;

use crate::{
    binary_option::{self, BinaryOption},
    column::Column,
    utility, variable_length_int,
};

const RUST_IPQS_READER_VERSION: u8 = 0x01;

const IPV4_MAP: u8 = 0b0000_0001;
const IPV6_MAP: u8 = 0b0000_0010;
const BLACKLIST_FILE: u8 = 0b0000_0100;
// const RESERVED_SEVEN: u8 = 0b0000_1000;
// const RESERVED_EIGHT: u8 = 0b0001_0000;
// const RESERVED_NINE: u8 = 0b0010_0000;
// const RESERVED_TEN: u8 = 0b0100_0000;
const BINARY_DATA: u8 = 0b1000_0000;

const COLUMN_DESCRIPTOR_LENGTH: usize = 24;

pub(crate) struct FileHeader {
    pub binary_data: bool,
    pub is_v6: bool,
    pub is_blacklist: bool,
    pub tree_start: u64,
    pub columns_bytes_length: usize,
    pub record_bytes_length: usize,
    // pub total_bytes: usize,
}

impl FileHeader {
    pub fn parse(header: &[u8]) -> Result<Self, Box<dyn Error>> {
        // first byte of header holds file option details
        let binary_option = BinaryOption { data: header[0] };

        let binary_data = binary_option.has(BINARY_DATA);

        let is_v6 = binary_option.has(IPV6_MAP);

        // file is only valid if IPv6 XOR IPv4
        let is_valid = is_v6 ^ binary_option.has(IPV4_MAP);
        if !is_valid {
            return Err("invalid file format, invalid first byte (EID 1)".into());
        }

        let is_blacklist = binary_option.has(BLACKLIST_FILE);

        // flat file db and library crate version must match
        if header[1] != RUST_IPQS_READER_VERSION {
            return Err("invalid file version (EID 2)".into());
        }

        // column pairs
        // header bytes 2,3,4 give the length of the header in bytes
        // the tree begins at the end of the header
        // after the first 11 bytes, the remaining bytes in the header are column headers
        // each header is 24 bytes long
        let tree_start = variable_length_int::uvarint64(&header[2..5])?;
        if tree_start == 0 {
            return Err("invalid file format, invalid header bytes (EID 3)".into());
        }
        let header_size: usize = tree_start.try_into()?;
        let column_bytes_length = header_size - 11;
        if column_bytes_length == 0 {
            return Err("file appears to be invalid, no column data found (EID 4)".into());
        }
        if column_bytes_length % COLUMN_DESCRIPTOR_LENGTH != 0 {
            return Err("invalid column data, too many or too few bytes (EID 5)".into());
        }

        let record_bytes: usize = variable_length_int::uvarint64(&header[5..7])?.try_into()?;
        if record_bytes == 0 {
            return Err("invalid file format, invalid record bytes (EID 6)".into());
        }

        // total bytes - should match file size in bytes
        // let total_bytes = utility::four_byte_int(&header[7..11]) as usize;
        Ok(FileHeader {
            binary_data,
            is_v6,
            is_blacklist,
            tree_start,
            columns_bytes_length: column_bytes_length,
            record_bytes_length: record_bytes,
            // total_bytes,
        })
    }
}

pub(crate) struct ColumnsBlock {
    pub columns: Vec<Column>,
}

impl ColumnsBlock {
    pub fn parse(file_header: &FileHeader, column_bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let number_of_columns = file_header.columns_bytes_length / COLUMN_DESCRIPTOR_LENGTH;
        let mut columns = Vec::new();
        // insert column name + record type pairs into column vector
        for column in 0..number_of_columns {
            // first 23 bytes of column header are 0-padded character strings
            let b = column * COLUMN_DESCRIPTOR_LENGTH;
            let e = (column + 1) * COLUMN_DESCRIPTOR_LENGTH - 1;
            // interpret the slice of bytes from 0-23 as UTF-8, trim the end, and take ownership
            let name = std::str::from_utf8(&column_bytes[b..e])?
                .trim_end_matches(char::from(0x00))
                .to_owned();
            // 24th byte is record type
            let record_type = column_bytes[e];
            columns.push(Column {
                name,
                record_type: BinaryOption { data: record_type },
                value: Default::default(), // empty String
            });
        }

        Ok(ColumnsBlock { columns })
    }
}

pub(crate) struct TreeHeader {
    pub tree_end: u64,
}

impl TreeHeader {
    pub fn parse(file_header: &FileHeader, tree_header: &[u8]) -> Result<Self, Box<dyn Error>> {
        let tree_type = BinaryOption {
            data: tree_header[0],
        };
        if !tree_type.has(binary_option::TREE_DATA) {
            return Err("file does not appear to be valid, bad binary tree (EID 7)".into());
        }
        let total_tree = utility::four_byte_int(&tree_header[1..5]);
        if total_tree == 0 {
            return Err("File does not appear to be valid, tree size is too small (EID 8)".into());
        }
        let tree_end: u64 = file_header.tree_start + total_tree;

        Ok(TreeHeader { tree_end })
    }
}

pub(crate) enum NodeResult {
    Missing,
    NextNode(u64),
    Record(u64),
}

#[inline]
pub fn next_node(bit: bool, node: &[u8], tree_start: u64, tree_end: u64) -> NodeResult {
    let value = if bit {
        // bit is 1 - go right
        utility::four_byte_int(&node[4..8])
    } else {
        // bit is 0 - go left
        utility::four_byte_int(&node[0..4])
    };
    match value {
        n if n < tree_start => NodeResult::Missing,
        n if n >= tree_end => NodeResult::Record(n),
        n => NodeResult::NextNode(n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_node(left: u32, right: u32) -> Vec<u8> {
        [left.to_le_bytes(), right.to_le_bytes()].concat()
    }

    #[test]
    fn test_next_node() {
        let node = create_node(10, 20);
        assert!(matches!(
            next_node(false, &node, 10, 100),
            NodeResult::NextNode(10)
        ));
        assert!(matches!(
            next_node(true, &node, 10, 100),
            NodeResult::NextNode(20)
        ));

        let node = create_node(0, 200);
        assert!(matches!(
            next_node(false, &node, 10, 100),
            NodeResult::Missing
        ));
        assert!(matches!(
            next_node(true, &node, 10, 100),
            NodeResult::Record(200)
        ));
    }
}
