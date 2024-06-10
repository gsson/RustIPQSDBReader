// Copyright IPQualityScore LLC 2023
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;

use crate::column::Column;
use crate::parse::{next_node, ColumnsBlock, FileHeader, NodeResult, TreeHeader};

use self::record::Record;

pub mod record;

/// The FileReader struct provides the interface for interacting with the flat file database.
/// For details, please reference the official
/// [IPQualityScore Flat File Database documentation](https://www.ipqualityscore.com/documentation/ip-reputation-database/overview)
#[derive(Debug)]
pub struct FileReader {
    reader: BufReader<File>,
    record_bytes: usize,
    tree_start: u64,
    tree_end: u64,
    is_v6: bool,
    binary_data: bool,
    columns: Vec<Column>,
    is_blacklist: bool,
}

impl FileReader {
    /// Opens the file at `Path` for reading and returns a FileReader interface
    /// ```
    /// use std::{error, path::PathBuf};
    /// use ipqs_db_reader::FileReader;
    /// let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    /// path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
    /// let mut reader = FileReader::open(&path_buf)?;
    /// # Ok::<(), Box <dyn error::Error>>(())
    /// ```
    pub fn open(file_path: &Path) -> Result<FileReader, Box<dyn Error>> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);

        //---------------- METADATA BEGIN

        // first 11 bytes reserved for file metadata
        let mut header = [0; 11];
        reader.read_exact(&mut header)?;
        let file_header = FileHeader::parse(&header)?;

        // consume column headers
        let mut column_bytes: Vec<u8> = vec![0; file_header.columns_bytes_length];
        reader.read_exact(&mut column_bytes)?;
        let columns = ColumnsBlock::parse(&file_header, &column_bytes)?;

        // Tree Metadata
        let mut tree_header = [0; 5];
        reader.read_exact(&mut tree_header)?;
        let tree_header = TreeHeader::parse(&file_header, &tree_header)?;

        Ok(FileReader {
            reader,
            binary_data: file_header.binary_data,
            is_v6: file_header.is_v6,
            // is_valid,
            is_blacklist: file_header.is_blacklist,
            //total_bytes,
            record_bytes: file_header.record_bytes_length,
            tree_start: file_header.tree_start,
            tree_end: tree_header.tree_end,
            columns: columns.columns,
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
        let mut node = [0u8; 8]; // each node has 2 ("left" and "right") 4-byte integer "pointers"
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
            let node_result = next_node(
                binary_representation[position],
                &node,
                self.tree_start,
                self.tree_end,
            );

            match node_result {
                NodeResult::Missing if self.is_blacklist => {
                    break;
                }
                NodeResult::Missing => {
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
                }
                NodeResult::NextNode(next_node) => {
                    file_position = next_node;
                    position += 1;
                }
                NodeResult::Record(record_position) => {
                    let mut raw: Vec<u8> = vec![0; self.record_bytes];
                    self.reader.seek(SeekFrom::Start(record_position))?;
                    self.reader.read_exact(&mut raw)?;
                    let record = Record::parse(raw, self)?;
                    return Ok(record);
                }
            }
        }
        Err("invalid or nonexistent IP specified for lookup (EID 10)".into())
    }

    fn get_ranged_string_value(
        reader: &mut BufReader<File>,
        offset: u64,
    ) -> Result<String, Box<dyn Error>> {
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
