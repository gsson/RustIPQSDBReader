use crate::binary_option as flag;
use crate::binary_option::BinaryOption;
use crate::memory_reader::MemoryReader;
use crate::memory_reader::Result;
use crate::Strictness;
use std::fmt;

#[derive(Clone)]
pub struct Record<'a, T> {
    memory: &'a MemoryReader<T>,
    offset: usize,
}

impl<'a, T: AsRef<[u8]>> fmt::Debug for Record<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl<'a, T: AsRef<[u8]>> fmt::Display for Record<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Connection Type: {}
Abuse Velocity: {}
Country: {:#?}
City: {:#?}
Region: {:#?}
ISP: {:#?}
Organization: {:#?}
ASN: {:#?}
Timezone: {:#?}
Latitude: {:#?}
Longitude: {:#?}
Fraud Score:
    Strictness (0): {:#?}
    Strictness (1): {:#?}
    Strictness (2): {:#?}
    Strictness (3): {:#?}
Is Proxy: {:#?}
Is VPN: {:#?}
Is Tor: {:#?}
Is Crawler: {:#?}
Is Bot: {:#?}
Recent Abuse: {:#?}
Is Blacklisted: {:#?}
Is Private: {:#?}
Is Mobile: {:#?}
Has Open Ports: {:#?}
Is Hosting Provider: {:#?}
Active VPN: {:#?}
Active Tor: {:#?}
Public Access Point: {:#?}",
            self.connection_type(),
            self.abuse_velocity(),
            self.country(),
            self.city(),
            self.region(),
            self.isp(),
            self.organization(),
            self.asn(),
            self.timezone(),
            self.latitude(),
            self.longitude(),
            self.fraud_score(Strictness::Zero),
            self.fraud_score(Strictness::One),
            self.fraud_score(Strictness::Two),
            self.fraud_score(Strictness::Three),
            self.is_proxy(),
            self.is_vpn(),
            self.is_tor(),
            self.is_crawler(),
            self.is_bot(),
            self.recent_abuse(),
            self.is_blacklisted(),
            self.is_private(),
            self.is_mobile(),
            self.has_open_ports(),
            self.is_hosting_provider(),
            self.active_vpn(),
            self.active_tor(),
            self.public_access_point(),
        )
    }
}

impl<'a, T: AsRef<[u8]>> Record<'a, T> {
    /// Parses the raw bytes at the leaf of the tree into a usable Record struct
    #[inline]
    pub(crate) fn parse(memory: &'a MemoryReader<T>, offset: usize) -> Result<Self> {
        Ok(Self { memory, offset })
    }

    #[inline(always)]
    fn common_byte(&self) -> u8 {
        let offset = self.offset + if self.memory.binary_data { 2 } else { 0 };
        self.memory.data.as_ref()[offset]
    }

    #[inline(always)]
    fn first_byte(&self) -> Option<u8> {
        self.memory
            .binary_data
            .then_some(self.memory.data.as_ref()[self.offset])
    }

    #[inline(always)]
    fn second_byte(&self) -> Option<u8> {
        self.memory
            .binary_data
            .then_some(self.memory.data.as_ref()[self.offset + 1])
    }

    #[inline]
    fn first_byte_flag(&self, flag: u8) -> Option<bool> {
        self.first_byte()
            .map(|data| BinaryOption { data }.has(flag))
    }

    #[inline]
    fn second_byte_flag(&self, flag: u8) -> Option<bool> {
        self.second_byte()
            .map(|data| BinaryOption { data }.has(flag))
    }

    #[inline]
    fn string_column(&self, column: Option<usize>) -> Option<&'a str> {
        column.and_then(|column_offset| {
            self.memory
                .get_ranged_string_value(self.offset + column_offset)
                .ok()
        })
    }

    #[inline]
    fn int_column(&self, column: Option<usize>) -> Option<u64> {
        column.map(|column_offset| self.memory.get_int_value(self.offset + column_offset))
    }

    #[inline]
    fn float_column(&self, column: Option<usize>) -> Option<f32> {
        column.map(|column_offset| self.memory.get_float_value(self.offset + column_offset))
    }

    pub fn is_proxy(&self) -> Option<bool> {
        self.first_byte_flag(flag::IS_PROXY)
    }

    pub fn is_vpn(&self) -> Option<bool> {
        self.first_byte_flag(flag::IS_VPN)
    }

    pub fn is_tor(&self) -> Option<bool> {
        self.first_byte_flag(flag::IS_TOR)
    }

    pub fn is_crawler(&self) -> Option<bool> {
        self.first_byte_flag(flag::IS_CRAWLER)
    }

    pub fn is_bot(&self) -> Option<bool> {
        self.first_byte_flag(flag::IS_BOT)
    }

    pub fn recent_abuse(&self) -> Option<bool> {
        self.first_byte_flag(flag::RECENT_ABUSE)
    }

    pub fn is_blacklisted(&self) -> Option<bool> {
        self.first_byte_flag(flag::IS_BLACKLISTED)
    }

    pub fn is_private(&self) -> Option<bool> {
        self.first_byte_flag(flag::IS_PRIVATE)
    }

    pub fn is_mobile(&self) -> Option<bool> {
        self.second_byte_flag(flag::IS_MOBILE)
    }

    pub fn has_open_ports(&self) -> Option<bool> {
        self.second_byte_flag(flag::HAS_OPEN_PORTS)
    }

    pub fn is_hosting_provider(&self) -> Option<bool> {
        self.second_byte_flag(flag::IS_HOSTING_PROVIDER)
    }

    pub fn active_vpn(&self) -> Option<bool> {
        self.second_byte_flag(flag::ACTIVE_VPN)
    }

    pub fn active_tor(&self) -> Option<bool> {
        self.second_byte_flag(flag::ACTIVE_TOR)
    }

    pub fn public_access_point(&self) -> Option<bool> {
        self.second_byte_flag(flag::PUBLIC_ACCESS_POINT)
    }

    pub fn connection_type(&self) -> &'static str {
        crate::file_reader::record::connection_type(self.common_byte())
    }

    pub fn abuse_velocity(&self) -> &'static str {
        crate::file_reader::record::abuse_velocity(self.common_byte())
    }

    pub fn country(&self) -> Option<&'a str> {
        self.string_column(self.memory.columns.country)
    }

    pub fn city(&self) -> Option<&'a str> {
        self.string_column(self.memory.columns.city)
    }

    pub fn region(&self) -> Option<&'a str> {
        self.string_column(self.memory.columns.region)
    }

    pub fn isp(&self) -> Option<&'a str> {
        self.string_column(self.memory.columns.isp)
    }

    pub fn organization(&self) -> Option<&'a str> {
        self.string_column(self.memory.columns.organization)
    }

    pub fn asn(&self) -> Option<u64> {
        self.int_column(self.memory.columns.asn)
    }

    pub fn timezone(&self) -> Option<&'a str> {
        self.string_column(self.memory.columns.timezone)
    }

    pub fn latitude(&self) -> Option<f32> {
        self.float_column(self.memory.columns.latitude)
    }

    pub fn longitude(&self) -> Option<f32> {
        self.float_column(self.memory.columns.longitude)
    }

    pub fn fraud_score(&self, strictness: Strictness) -> Option<u32> {
        let offset = match strictness {
            Strictness::Zero => self.memory.columns.fraud_score[0],
            Strictness::One => self.memory.columns.fraud_score[1],
            Strictness::Two => self.memory.columns.fraud_score[2],
            Strictness::Three => self.memory.columns.fraud_score[3],
        };
        offset.map(|column_offset| self.memory.get_small_int_value(self.offset + column_offset))
    }

    pub fn to_file_record(&self) -> crate::Record {
        crate::Record {
            is_proxy: self.is_proxy(),
            is_vpn: self.is_vpn(),
            is_tor: self.is_tor(),
            is_crawler: self.is_crawler(),
            is_bot: self.is_bot(),
            recent_abuse: self.recent_abuse(),
            is_blacklisted: self.is_blacklisted(),
            is_private: self.is_private(),
            is_mobile: self.is_mobile(),
            has_open_ports: self.has_open_ports(),
            is_hosting_provider: self.is_hosting_provider(),
            active_vpn: self.active_vpn(),
            active_tor: self.active_tor(),
            public_access_point: self.public_access_point(),
            connection_type: self.connection_type().to_string(),
            abuse_velocity: self.abuse_velocity().to_string(),
            country: self.country().map(|s| s.to_string()),
            city: self.city().map(|s| s.to_string()),
            region: self.region().map(|s| s.to_string()),
            isp: self.isp().map(|s| s.to_string()),
            organization: self.organization().map(|s| s.to_string()),
            asn: self.asn(),
            timezone: self.timezone().map(|s| s.to_string()),
            latitude: self.latitude(),
            longitude: self.longitude(),
            fraud_score: crate::file_reader::record::FraudScore {
                strictness: [
                    self.fraud_score(Strictness::Zero),
                    self.fraud_score(Strictness::One),
                    self.fraud_score(Strictness::Two),
                    self.fraud_score(Strictness::Three),
                ],
            },
            columns: Vec::new(),
        }
    }
}
