// Copyright IPQualityScore LLC 2023
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;

use crate::binary_option as flag;
use crate::binary_option::BinaryOption;
use crate::column::Column;
use crate::utility;

mod variable_length_int;

pub mod record;

const RUST_IPQS_READER_VERSION: u8 = 0x01;

const IPV4_MAP: u8 = 0b0000_0001;
const IPV6_MAP: u8 = 0b0000_0010;
const BLACKLIST_FILE: u8 = 0b0000_0100;
// const RESERVED_SEVEN: u8 = 0b0000_1000;
// const RESERVED_EIGHT: u8 = 0b0001_0000;
// const RESERVED_NINE: u8 = 0b0010_0000;
// const RESERVED_TEN: u8 = 0b0100_0000;
const BINARY_DATA: u8 = 0b1000_0000;

/// The FileReader struct provides the interface for interacting with the flat file database.
/// For details, please reference the official
/// [IPQualityScore Flat File Database documentation](https://www.ipqualityscore.com/documentation/ip-reputation-database/overview)
#[derive(Debug)]
pub struct FileReader<R> {
    reader: R,
    record_bytes: usize,
    tree_start: u64,
    tree_end: u64,
    is_v6: bool,
    binary_data: bool,
    columns: Vec<Column>,
    is_blacklist: bool,
}

impl FileReader<BufReader<File>> {
    /// Opens the file at `Path` for reading and returns a FileReader interface
    /// ```
    /// use std::{error, path::PathBuf};
    /// use ipqs_db_reader::FileReader;
    /// let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    /// path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
    /// let mut reader = FileReader::open(&path_buf)?;
    /// # Ok::<(), Box <dyn error::Error>>(())
    /// ```
    pub fn open(file_path: &Path) -> Result<Self, Box<dyn Error>> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        FileReader::from_reader(reader)
    }
}

impl<T: AsRef<[u8]>> FileReader<Cursor<T>> {
    /// Open a file reader from a vec of bytes
    pub fn from_bytes(bytes: T) -> Result<Self, Box<dyn Error>> {
        let reader = Cursor::new(bytes);
        FileReader::from_reader(reader)
    }
}

impl<R: Read + Seek> FileReader<R> {
    /// Create file reader
    pub fn from_reader(mut reader: R) -> Result<Self, Box<dyn Error>> {
        //---------------- METADATA BEGIN

        // first 11 bytes reserved for file metadata
        let mut header = [0; 11];
        reader.read_exact(&mut header)?;

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
        if column_bytes_length % 24 != 0 {
            return Err("invalid column data, too many or too few bytes (EID 5)".into());
        }

        let record_bytes: usize = variable_length_int::uvarint64(&header[5..7])?.try_into()?;
        if record_bytes == 0 {
            return Err("invalid file format, invalid record bytes (EID 6)".into());
        }

        // total bytes - should match file size in bytes
        //let total_bytes = utility::four_byte_int(&header[7..11]);

        //---------------- METADATA END

        // consume column headers
        let number_of_columns = column_bytes_length / 24;
        let mut column_bytes: Vec<u8> = vec![0; column_bytes_length];
        reader.read_exact(&mut column_bytes)?;
        let mut columns = Vec::new();
        // insert column name + record type pairs into column vector
        for column in 0..number_of_columns {
            // first 23 bytes of column header are 0-padded character strings
            let b = column * 24;
            let e = (column + 1) * 24 - 1;
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

        // Tree Metadata
        let mut tree_header: Vec<u8> = vec![0; 5];
        reader.read_exact(&mut tree_header)?;
        let tree_type = BinaryOption {
            data: tree_header[0],
        };
        if !tree_type.has(flag::TREE_DATA) {
            return Err("file does not appear to be valid, bad binary tree (EID 7)".into());
        }
        let total_tree = utility::four_byte_int(&tree_header[1..5]);
        if total_tree == 0 {
            return Err("File does not appear to be valid, tree size is too small (EID 8)".into());
        }
        let tree_end: u64 = tree_start + total_tree;

        Ok(FileReader {
            reader,
            binary_data,
            is_v6,
            // is_valid,
            is_blacklist,
            //total_bytes,
            record_bytes,
            tree_start,
            tree_end,
            columns,
        })
    }

    /// Retrieve the record associated with `IpAddr`, if one exists
    /// ```
    /// # use std::path::PathBuf;
    /// use ipqs_db_reader::FileReader;
    /// use std::{
    ///     error,
    ///     net::{IpAddr, Ipv4Addr},
    ///     str::FromStr};
    /// let ip: IpAddr = IpAddr::V4(Ipv4Addr::from_str("8.8.0.0")?);
    /// # let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    /// # path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
    /// # let mut reader = FileReader::open(&path_buf)?;
    /// let record = reader.fetch(&ip)?;
    /// # Ok::<(), Box <dyn error::Error>>(())
    /// ```
    pub fn fetch(&mut self, ip: &IpAddr) -> Result<record::Record, Box<dyn Error>> {
        if self.is_v6 && ip.is_ipv4() {
            return Err("attempted to fetch IPv4 record using IPv6 data file".into());
        }
        if !self.is_v6 && ip.is_ipv6() {
            return Err("attempted to fetch IPv6 record using IPv4 data file".into());
        }

        let mut position: usize = 0; // bit within binary representation of ip address
        let mut previous: // maps bits within binary representation to node positions within tree
            HashMap<usize, u64> = HashMap::new(); // (for going back up tree if ip address not found)
        let mut file_position = self.tree_start + 5; // start traversing tree just after tree header
        let mut node: Vec<u8> = vec![0u8; 8]; // each node has 2 ("left" and "right") 4-byte integer "pointers"
        let mut binary_representation: Vec<bool> = Vec::new();
        match ip {
            IpAddr::V4(ipv4) => {
                for octet in ipv4.octets() {
                    for s in 0..8 {
                        let mask = 0x80 >> s;
                        binary_representation.push(octet & mask != 0);
                    }
                }
            }
            IpAddr::V6(ipv6) => {
                for segment in ipv6.segments() {
                    for s in 0..16 {
                        let mask = 0x8000 >> s;
                        binary_representation.push(segment & mask != 0);
                    }
                }
            }
        }

        // loop over tree, aborting after too many iterations
        for _ in 0..257 {
            previous.insert(position, file_position);
            if binary_representation.len() <= position {
                // somehow we went through the whole binary representation without finding a record
                return Err("invalid or nonexistent IP specified for lookup (EID 9)".into());
            }
            self.reader.seek(SeekFrom::Start(file_position))?;
            self.reader.read_exact(&mut node)?;
            if binary_representation[position] {
                // bit is 1 - go right
                file_position = utility::four_byte_int(&node[4..8]);
            } else {
                // bit is 0 - go left
                file_position = utility::four_byte_int(&node[0..4]);
            }

            if !self.is_blacklist && file_position == 0 {
                // specified ip is not in the file
                // go back up the tree until we reach a 1,
                // take the 0 path, and follow all right children until we reach a record
                // or another 0
                for i in 0..position + 1 {
                    if binary_representation[position - i] {
                        binary_representation[position - i] = false;
                        //for n in position - i + 1..binary_representation.len() { // <-- before clippy
                        for bit in binary_representation.iter_mut().skip(position - i + 1) {
                            *bit = true;
                        }
                        position -= i;
                        file_position = previous[&position];
                        break;
                    }
                }
                continue;
            }

            if file_position < self.tree_end {
                // there is still more tree left
                if file_position == 0 {
                    break;
                }
                position += 1;
                continue;
            }

            // -------- Record found
            let mut raw: Vec<u8> = vec![0; self.record_bytes];
            self.reader.seek(SeekFrom::Start(file_position))?;
            self.reader.read_exact(&mut raw)?;
            let record = self::record::Record::parse(raw, self)?;
            return Ok(record);
        }
        Err("invalid or nonexistent IP specified for lookup (EID 10)".into())
    }

    fn get_ranged_string_value(reader: &mut R, offset: u64) -> Result<String, Box<dyn Error>> {
        reader.seek(SeekFrom::Start(offset))?;
        let mut size_buf: Vec<u8> = vec![0; 1];
        reader.read_exact(&mut size_buf)?;
        let size: usize = usize::from(size_buf[0]);
        let mut raw: Vec<u8> = vec![0; size];
        reader.read_exact(&mut raw)?;
        let value = String::from_utf8(raw)?;

        Ok(value)
    }

    /// Returns true if the file contains IPv6 addresses
    pub fn is_ipv6(&self) -> bool {
        self.is_v6
    }

    /// Returns true if the file is a blacklist file
    pub fn is_blacklist(&self) -> bool {
        self.is_blacklist
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    #[test]
    fn no_file_path() {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("BAD_FILE_NAME");
        let file_reader = FileReader::open(&path_buf);
        assert!(file_reader.is_err());
    }

    #[test]
    fn open_file() -> Result<(), Box<dyn Error>> {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
        FileReader::open(&path_buf)?;

        Ok(())
    }

    #[test]
    fn from_bytes() -> Result<(), Box<dyn Error>> {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
        let bytes = std::fs::read(path_buf)?;
        FileReader::from_bytes(bytes)?;

        Ok(())
    }

    #[test]
    fn columns() -> Result<(), Box<dyn Error>> {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
        let file_reader = FileReader::open(&path_buf)?;
        assert_eq!(file_reader.columns.len(), 11);
        Ok(())
    }

    #[test]
    fn fetch_basic_ipv4() -> Result<(), Box<dyn Error>> {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
        let mut file_reader = FileReader::open(&path_buf)?;
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::from([8, 8, 0, 0]));
        let record = file_reader.fetch(&ip)?;
        dbg!(record);
        Ok(())
    }

    #[test]
    fn fetch_basic_ipv6() -> Result<(), Box<dyn Error>> {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv6.ipqs");
        let mut file_reader = FileReader::open(&path_buf)?;
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::from([
            0x2001, 0x4860, 0x4860, 0x0000, 0x0000, 0x0000, 0x0000, 0x8844,
        ]));
        let record = file_reader.fetch(&ip)?;
        dbg!(record);
        Ok(())
    }
}
