use std::{net::IpAddr, path::Path};
mod record;

pub use record::Record;

use crate::{
    binary_option as flag,
    column::Column,
    parse::{next_node, ColumnsBlock, FileHeader, NodeResult, TreeHeader},
    utility,
};

type BoxError = Box<dyn std::error::Error>;
type Result<T, E = BoxError> = std::result::Result<T, E>;

pub(crate) struct Columns {
    asn: Option<usize>,
    latitude: Option<usize>,
    longitude: Option<usize>,
    fraud_score: [Option<usize>; 4],
    country: Option<usize>,
    city: Option<usize>,
    region: Option<usize>,
    isp: Option<usize>,
    organization: Option<usize>,
    timezone: Option<usize>,
}

fn column_size(column: &Column) -> usize {
    if column.record_type.has(flag::STRING_DATA)
        || column.record_type.has(flag::INT_DATA)
        || column.record_type.has(flag::FLOAT_DATA)
    {
        4
    } else {
        1
    }
}

impl Columns {
    fn new(file_header: &FileHeader, columns: ColumnsBlock) -> Self {
        let mut column_offset = if file_header.binary_data { 3 } else { 1 };
        let mut asn = None;
        let mut latitude = None;
        let mut longitude = None;
        let mut fraud_score = [None; 4];
        let mut country = None;
        let mut city = None;
        let mut region = None;
        let mut isp = None;
        let mut organization = None;
        let mut timezone = None;

        for column in &columns.columns {
            match column.name.as_str() {
                "ASN" => {
                    asn = Some(column_offset);
                }
                "Latitude" => {
                    latitude = Some(column_offset);
                }
                "Longitude" => {
                    longitude = Some(column_offset);
                }
                "ZeroFraudScore" => {
                    fraud_score[0] = Some(column_offset);
                }
                "OneFraudScore" => {
                    fraud_score[1] = Some(column_offset);
                }
                "TwoFraudScore" => {
                    fraud_score[2] = Some(column_offset);
                }
                "ThreeFraudScore" => {
                    fraud_score[3] = Some(column_offset);
                }
                "Country" => {
                    country = Some(column_offset);
                }
                "City" => {
                    city = Some(column_offset);
                }
                "Region" => {
                    region = Some(column_offset);
                }
                "ISP" => {
                    isp = Some(column_offset);
                }
                "Organization" => {
                    organization = Some(column_offset);
                }
                "Timezone" => {
                    timezone = Some(column_offset);
                }
                _ => {}
            }
            column_offset += column_size(column);
        }

        Self {
            asn,
            latitude,
            longitude,
            fraud_score,
            country,
            city,
            region,
            isp,
            organization,
            timezone,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct AddressBits(u128, u32);

impl From<IpAddr> for AddressBits {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self(u32::from_be_bytes(ip.octets()) as u128, 32),
            IpAddr::V6(ip) => Self(u128::from_be_bytes(ip.octets()), 128),
        }
    }
}

impl AddressBits {
    #[inline(always)]
    const fn bit(&self, index: u32) -> u128 {
        1 << (self.1 - index - 1)
    }
    #[inline(always)]
    const fn position(&self, index: usize) -> bool {
        self.0 & self.bit(index as u32) != 0
    }

    #[inline]
    fn set_branch(&mut self, index: u32) {
        let bit = self.bit(index);
        let tail = bit - 1;
        let mask = u128::MAX << (self.1 - index);

        self.0 = (self.0 & mask) | tail;
    }

    #[inline]
    fn find_previous_one(&self, index: u32) -> Option<u32> {
        let mask = u128::MAX << (self.1 - 1 - index);
        let tz = (self.0 & mask).trailing_zeros();
        if tz == u128::BITS {
            return None;
        }
        Some(self.1 - 1 - tz)
    }

    #[inline]
    fn try_backtrack(&mut self, index: usize) -> Option<usize> {
        let index = self.find_previous_one(index as u32)?;
        self.set_branch(index);
        Some(index as usize)
    }
}

pub struct MemoryReader<T> {
    data: T,
    pub(crate) binary_data: bool,
    is_v6: bool,
    is_blacklist: bool,
    tree_block_start: u64,
    tree_block_end: u64,
    pub(crate) columns: Columns,
}

impl MemoryReader<Vec<u8>> {
    /// Opens the file at `Path` for reading, reads its contents and returns a
    /// MemoryReader interface
    /// ```
    /// use std::{error, path::PathBuf};
    /// use ipqs_db_reader::MemoryReader;
    /// let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    /// path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
    /// let reader = MemoryReader::open(&path_buf)?;
    /// # Ok::<(), Box <dyn error::Error>>(())
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(data)
    }
}

impl<T: AsRef<[u8]>> MemoryReader<T> {
    /// Creates a MemoryReader interface from a collection of bytes
    /// ```
    /// use std::{error, path::PathBuf};
    /// use ipqs_db_reader::MemoryReader;
    /// let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    /// path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
    /// let data = std::fs::read(&path_buf)?;
    /// let reader = MemoryReader::from_bytes(data)?;
    /// # Ok::<(), Box <dyn error::Error>>(())
    /// ```
    pub fn from_bytes(data: T) -> Result<Self> {
        let slice = data.as_ref();
        let (file_header, tail) = slice.split_at(11);
        let file_header = FileHeader::parse(file_header)?;

        // consume column headers
        let (columns, tail) = tail.split_at(file_header.columns_bytes_length);
        let columns = ColumnsBlock::parse(&file_header, columns)?;
        let columns = Columns::new(&file_header, columns);

        // Tree Metadata
        let tree_header = TreeHeader::parse(&file_header, tail)?;

        Ok(Self {
            data,
            binary_data: file_header.binary_data,
            is_v6: file_header.is_v6,
            is_blacklist: file_header.is_blacklist,
            tree_block_start: file_header.tree_start,
            tree_block_end: tree_header.tree_end,
            columns,
        })
    }

    /// Retrieve the record associated with `IpAddr`, if one exists
    /// ```
    /// # use std::path::PathBuf;
    /// use ipqs_db_reader::MemoryReader;
    /// use std::{error, net::IpAddr, str::FromStr};
    /// let ip: IpAddr = IpAddr::from_str("8.8.0.0")?;
    /// # let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    /// # path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
    /// # let reader = MemoryReader::open(&path_buf)?;
    /// let record = reader.fetch(&ip)?;
    /// # Ok::<(), Box <dyn error::Error>>(())
    /// ```
    pub fn fetch(&self, ip: &IpAddr) -> Result<record::Record<T>> {
        if self.is_v6 && ip.is_ipv4() {
            return Err("attempted to fetch IPv4 record using IPv6 data file".into());
        }
        if !self.is_v6 && ip.is_ipv6() {
            return Err("attempted to fetch IPv6 record using IPv4 data file".into());
        }

        let mut bit_position = 0; // bit within binary representation of ip address
        let mut node_position = self.tree_block_start + 5; // start traversing tree just after tree header
        let mut address_bits = AddressBits::from(*ip);
        let mut previous = [0; 128];

        let data = self.data.as_ref();
        // loop over tree, aborting after too many iterations
        for _ in 0..257 {
            previous[bit_position] = node_position;
            if address_bits.1 as usize <= bit_position {
                // somehow we went through the whole binary representation without finding a record
                return Err("invalid or nonexistent IP specified for lookup (EID 9)".into());
            }
            let node_result = next_node(
                address_bits.position(bit_position),
                &data[node_position as usize..(node_position + 8) as usize],
                self.tree_block_start,
                self.tree_block_end,
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
                    if let Some(new_position) = address_bits.try_backtrack(bit_position) {
                        bit_position = new_position;
                        node_position = previous[bit_position];
                    }
                }
                NodeResult::NextNode(next_node) => {
                    node_position = next_node;
                    bit_position += 1;
                }
                NodeResult::Record(record_position) => {
                    let record = Record::parse(self, record_position as usize)?;
                    return Ok(record);
                }
            }
        }
        Err("invalid or nonexistent IP specified for lookup (EID 10)".into())
    }

    pub(crate) fn get_ranged_string_value(&self, offset: usize) -> Result<&str> {
        let data = self.data.as_ref();
        let offset = utility::four_byte_int(&data[offset..offset + 4]);
        utility::parse_string(&data[offset as usize..])
    }

    pub(crate) fn get_small_int_value(&self, offset: usize) -> u32 {
        let data = self.data.as_ref();
        u32::from(data[offset])
    }

    pub(crate) fn get_int_value(&self, offset: usize) -> u64 {
        let data = self.data.as_ref();
        utility::four_byte_int(&data[offset..offset + 4])
    }

    pub(crate) fn get_float_value(&self, offset: usize) -> f32 {
        let data = self.data.as_ref();
        utility::four_byte_float(&data[offset..offset + 4])
    }
}

#[cfg(test)]
mod tests {
    use crate::file_reader::FileReader;
    use crate::{file_reader, Strictness};

    use super::*;
    use std::error::Error;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::str::FromStr as _;

    use rand::RngCore;

    fn compare_records<T: AsRef<[u8]>>(
        memory_record: &Record<'_, T>,
        file_record: &file_reader::record::Record,
    ) {
        assert_eq!(
            file_record.connection_type(),
            memory_record.connection_type()
        );
        assert_eq!(file_record.abuse_velocity(), memory_record.abuse_velocity());
        assert_eq!(file_record.country(), memory_record.country());
        assert_eq!(file_record.city(), memory_record.city());
        assert_eq!(file_record.region(), memory_record.region());
        assert_eq!(file_record.isp(), memory_record.isp());
        assert_eq!(file_record.organization(), memory_record.organization());
        assert_eq!(file_record.asn(), memory_record.asn());
        assert_eq!(file_record.timezone(), memory_record.timezone());
        assert_eq!(file_record.latitude(), memory_record.latitude());
        assert_eq!(file_record.longitude(), memory_record.longitude());
        assert_eq!(
            file_record.fraud_score(Strictness::Zero),
            memory_record.fraud_score(Strictness::Zero)
        );
        assert_eq!(
            file_record.fraud_score(Strictness::One),
            memory_record.fraud_score(Strictness::One)
        );
        assert_eq!(
            file_record.fraud_score(Strictness::Two),
            memory_record.fraud_score(Strictness::Two)
        );
        assert_eq!(
            file_record.fraud_score(Strictness::Three),
            memory_record.fraud_score(Strictness::Three)
        );
        assert_eq!(file_record.is_proxy(), memory_record.is_proxy());
        assert_eq!(file_record.is_vpn(), memory_record.is_vpn());
        assert_eq!(file_record.is_tor(), memory_record.is_tor());
        assert_eq!(file_record.is_crawler(), memory_record.is_crawler());
        assert_eq!(file_record.is_bot(), memory_record.is_bot());
        assert_eq!(file_record.recent_abuse(), memory_record.recent_abuse());
        assert_eq!(file_record.is_blacklisted(), memory_record.is_blacklisted());
        assert_eq!(file_record.is_private(), memory_record.is_private());
        assert_eq!(file_record.is_mobile(), memory_record.is_mobile());
        assert_eq!(file_record.has_open_ports(), memory_record.has_open_ports());
        assert_eq!(
            file_record.is_hosting_provider(),
            memory_record.is_hosting_provider()
        );
        assert_eq!(file_record.active_vpn(), memory_record.active_vpn());
        assert_eq!(file_record.active_tor(), memory_record.active_tor());
        assert_eq!(
            file_record.public_access_point(),
            memory_record.public_access_point()
        );
    }

    fn address_from_u32(bits: u32) -> AddressBits {
        let ip = IpAddr::from(u32::to_be_bytes(bits));
        AddressBits::from(ip)
    }

    #[test]
    fn from_bytes() -> Result<(), Box<dyn Error>> {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
        let bytes = std::fs::read(path_buf)?;

        let _ = MemoryReader::from_bytes(bytes)?;

        Ok(())
    }

    #[test]
    fn open() -> Result<(), Box<dyn Error>> {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");

        let _ = MemoryReader::open(path_buf)?;

        Ok(())
    }

    #[test]
    fn file_reader_parity_known_ips() -> Result<(), Box<dyn Error>> {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
        let memory = MemoryReader::open(&path_buf)?;
        let mut file = FileReader::open(&path_buf)?;

        for ip in [
            "5.31.240.127",
            "5.109.145.38",
            "8.8.0.0",
            "37.164.98.162",
            "37.211.187.84",
            "54.36.149.33",
            "80.134.137.226",
            "81.153.251.46",
            "82.42.151.147",
            "91.73.59.134",
            "92.99.46.209",
            "94.24.101.60",
            "94.203.137.10",
            "103.5.232.145",
            "109.27.79.126",
            "135.181.42.89",
            "150.129.54.111",
            "157.230.53.4",
            "176.145.179.123",
            "178.24.249.40",
            "185.83.197.154",
            "188.135.112.58",
            "195.239.217.102",
            "212.70.116.218",
        ] {
            let ip = IpAddr::from_str(ip)?;
            let memory_record = memory.fetch(&ip);
            let file_record = file.fetch(&ip);

            match (memory_record, file_record) {
                (Err(e), Err(f)) => {
                    assert_eq!(e.to_string(), f.to_string());
                }
                (Ok(memory_record), Ok(file_record)) => {
                    compare_records(&memory_record, &file_record)
                }
                _ => unreachable!("records should have the same status"),
            }
        }

        Ok(())
    }

    #[test]
    fn file_reader_parity_random_ips() -> Result<(), Box<dyn Error>> {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");

        let memory = MemoryReader::open(&path_buf)?;
        let mut file = FileReader::open(&path_buf)?;

        let mut rng = rand::thread_rng();
        let mut ip = [0u8; 4];
        for _ in 0..1000 {
            rng.fill_bytes(&mut ip);
            let ip = IpAddr::from(ip);

            let memory_record = memory.fetch(&ip);
            let file_record = file.fetch(&ip);

            match (memory_record, file_record) {
                (Err(e), Err(f)) => {
                    assert_eq!(e.to_string(), f.to_string());
                }
                (Ok(memory_record), Ok(file_record)) => {
                    compare_records(&memory_record, &file_record)
                }
                _ => unreachable!("records should have the same status"),
            }
        }

        Ok(())
    }

    #[test]
    fn fetch_basic_ipv4() -> Result<(), Box<dyn Error>> {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");

        let memory = MemoryReader::open(path_buf)?;
        let ip = IpAddr::from([8, 8, 0, 0]);
        let record = memory.fetch(&ip)?;
        dbg!(record);
        Ok(())
    }

    #[test]
    fn fetch_basic_ipv6() -> Result<(), Box<dyn Error>> {
        let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv6.ipqs");

        let memory = MemoryReader::open(path_buf)?;
        let ip = IpAddr::from([
            0x2001, 0x4860, 0x4860, 0x0000, 0x0000, 0x0000, 0x0000, 0x8844,
        ]);
        let record = memory.fetch(&ip)?;
        dbg!(record);
        Ok(())
    }

    #[test]
    fn test_address_bits_position() {
        let ip = address_from_u32(0b00000000_00000000_00000000_00000000);
        for i in 0..32 {
            assert!(!ip.position(i), "position = {i}");
        }

        let ip = address_from_u32(0b11111111_11111111_11111111_11111111);
        for i in 0..32 {
            assert!(ip.position(i), "position = {i}");
        }

        let ip = address_from_u32(0b10000000_00000000_00000000_00000000);
        assert!(ip.position(0), "position = 0");
        for i in 1..32 {
            assert!(!ip.position(i), "position = {i}");
        }

        let ip = address_from_u32(0b00000000_00000000_00000000_00000001);
        for i in 0..31 {
            assert!(!ip.position(i), "position = {i}");
        }
        assert!(ip.position(31), "position = 31");
    }

    #[test]
    fn test_address_try_backtrack() {
        let mut ip = address_from_u32(0b10000000_00000000_10000000_00000000);
        let expected = address_from_u32(0b10000000_00000000_01111111_11111111);
        let new_position = ip.try_backtrack(31);
        assert_eq!(ip, expected);
        assert_eq!(new_position, Some(16));

        let mut ip = address_from_u32(0b10000000_00000000_10000000_00000000);
        let expected = address_from_u32(0b10000000_00000000_01111111_11111111);
        let new_position = ip.try_backtrack(16);
        assert_eq!(ip, expected);
        assert_eq!(new_position, Some(16));

        let mut ip = address_from_u32(0b10000000_00000000_10000000_00000000);
        let expected = address_from_u32(0b01111111_11111111_11111111_11111111);
        let new_position = ip.try_backtrack(15);
        assert_eq!(ip, expected);
        assert_eq!(new_position, Some(0));

        let mut ip = address_from_u32(0b00000000_00000000_00000000_00000000);
        let expected = address_from_u32(0b00000000_00000000_00000000_00000000);
        let new_position = ip.try_backtrack(31);
        assert_eq!(ip, expected);
        assert_eq!(new_position, None);
    }
}
