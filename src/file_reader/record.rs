// Copyright 2023 IPQualityScore LLC
use crate::binary_option as flag;
use crate::binary_option::BinaryOption;
use crate::column::Column;
use crate::file_reader::FileReader;
use crate::utility;
use std::error::Error;
use std::fmt;

/// How in depth (strict) do you want this query to be? Higher values
/// may provide a higher false-positive rate. We recommend starting at "0", the lowest strictness setting,
/// and increasing to "1" depending on your levels of fraud. Levels 2+ are VERY strict and will produce false-positives.
/// Note that not all files have values for each level of strictness.
pub enum Strictness {
    Zero,
    One,
    Two,
    Three,
}

/// Details all available information about the target IP address.
/// Depending on your version of the flat file database, your file may or may not
/// have some fields, such as is_proxy, is_vpn, is_tor, etc.
///
/// For more details about any of the particular values, please see the
/// official [IPQualityScore Flat File Database documentation](https://www.ipqualityscore.com/documentation/ip-reputation-database/overview).
#[derive(Clone, Default, Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct Record {
    pub(crate) connection_type: String,
    pub(crate) abuse_velocity: String,
    pub(crate) country: Option<String>,
    pub(crate) city: Option<String>,
    pub(crate) region: Option<String>,
    pub(crate) isp: Option<String>,
    pub(crate) organization: Option<String>,
    pub(crate) asn: Option<u64>,
    pub(crate) timezone: Option<String>,
    pub(crate) latitude: Option<f32>,
    pub(crate) longitude: Option<f32>,
    pub(crate) fraud_score: FraudScore,
    pub(crate) is_proxy: Option<bool>,
    pub(crate) is_vpn: Option<bool>,
    pub(crate) is_tor: Option<bool>,
    pub(crate) is_crawler: Option<bool>,
    pub(crate) is_bot: Option<bool>,
    pub(crate) recent_abuse: Option<bool>,
    pub(crate) is_blacklisted: Option<bool>,
    pub(crate) is_private: Option<bool>,
    pub(crate) is_mobile: Option<bool>,
    pub(crate) has_open_ports: Option<bool>,
    pub(crate) is_hosting_provider: Option<bool>,
    pub(crate) active_vpn: Option<bool>,
    pub(crate) active_tor: Option<bool>,
    pub(crate) public_access_point: Option<bool>,

    #[cfg_attr(feature = "json", serde(skip_serializing))]
    pub(crate) columns: Vec<Column>,
}

impl fmt::Display for Record {
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
            self.connection_type,
            self.abuse_velocity,
            self.country,
            self.city,
            self.region,
            self.isp,
            self.organization,
            self.asn,
            self.timezone,
            self.latitude,
            self.longitude,
            self.fraud_score.strictness[0],
            self.fraud_score.strictness[1],
            self.fraud_score.strictness[2],
            self.fraud_score.strictness[3],
            self.is_proxy,
            self.is_vpn,
            self.is_tor,
            self.is_crawler,
            self.is_bot,
            self.recent_abuse,
            self.is_blacklisted,
            self.is_private,
            self.is_mobile,
            self.has_open_ports,
            self.is_hosting_provider,
            self.active_vpn,
            self.active_tor,
            self.public_access_point,
        )
    }
}

impl Record {
    /// Parses the raw bytes at the leaf of the tree into a usable Record struct
    pub(crate) fn parse(raw: Vec<u8>, file: &mut FileReader) -> Result<Record, Box<dyn Error>> {
        let mut current_byte = 0;
        let mut record = Record::default();
        // files with the binary data flag set have two additional bytes per record
        if file.binary_data {
            // byte 1
            let first_byte = BinaryOption { data: raw[0] };
            record.is_proxy = Some(first_byte.has(flag::IS_PROXY));
            record.is_vpn = Some(first_byte.has(flag::IS_VPN));
            record.is_tor = Some(first_byte.has(flag::IS_TOR));
            record.is_crawler = Some(first_byte.has(flag::IS_CRAWLER));
            record.is_bot = Some(first_byte.has(flag::IS_BOT));
            record.recent_abuse = Some(first_byte.has(flag::RECENT_ABUSE));
            record.is_blacklisted = Some(first_byte.has(flag::IS_BLACKLISTED));
            record.is_private = Some(first_byte.has(flag::IS_PRIVATE));
            // byte 2
            let second_byte = BinaryOption { data: raw[1] };
            record.is_mobile = Some(second_byte.has(flag::IS_MOBILE));
            record.has_open_ports = Some(second_byte.has(flag::HAS_OPEN_PORTS));
            record.is_hosting_provider = Some(second_byte.has(flag::IS_HOSTING_PROVIDER));
            record.active_vpn = Some(second_byte.has(flag::ACTIVE_VPN));
            record.active_tor = Some(second_byte.has(flag::ACTIVE_TOR));
            record.public_access_point = Some(second_byte.has(flag::PUBLIC_ACCESS_POINT));

            current_byte = 2;
        }
        // files with or without binary data share connection type/abuse velocity byte
        let common_byte = raw[current_byte];
        current_byte += 1;

        record.connection_type = connection_type(common_byte).to_string();
        record.abuse_velocity = abuse_velocity(common_byte).to_string();

        // columns
        let mut value: String;
        for c in 0..file.columns.len() {
            let column = &(file.columns[c]);
            match column.name.as_str() {
                "ASN" => {
                    let u = utility::four_byte_int(&raw[current_byte..current_byte + 4]);
                    record.asn = Some(u);
                    value = u.to_string();
                    record.columns.push(Column {
                        name: column.name.clone(),
                        record_type: BinaryOption {
                            data: flag::INT_DATA,
                        },
                        value,
                    });
                    current_byte += 4;
                }
                "Latitude" => {
                    let f = utility::four_byte_float(&raw[current_byte..current_byte + 4]);
                    record.latitude = Some(f);
                    value = f.to_string();
                    record.columns.push(Column {
                        name: column.name.clone(),
                        record_type: BinaryOption {
                            data: flag::FLOAT_DATA,
                        },
                        value,
                    });
                    current_byte += 4;
                }
                "Longitude" => {
                    let f = utility::four_byte_float(&raw[current_byte..current_byte + 4]);
                    record.longitude = Some(f);
                    value = f.to_string();
                    record.columns.push(Column {
                        name: column.name.clone(),
                        record_type: BinaryOption {
                            data: flag::FLOAT_DATA,
                        },
                        value,
                    });
                    current_byte += 4;
                }
                "ZeroFraudScore" => {
                    let u = u32::from(raw[current_byte]);
                    record.fraud_score.strictness[0] = Some(u);
                    value = u.to_string();
                    record.columns.push(Column {
                        name: column.name.clone(),
                        record_type: BinaryOption {
                            data: flag::SMALL_INT_DATA,
                        },
                        value,
                    });
                    current_byte += 1;
                }
                "OneFraudScore" => {
                    let u = u32::from(raw[current_byte]);
                    record.fraud_score.strictness[1] = Some(u);
                    value = u.to_string();
                    record.columns.push(Column {
                        name: column.name.clone(),
                        record_type: BinaryOption {
                            data: flag::SMALL_INT_DATA,
                        },
                        value,
                    });
                    current_byte += 1;
                }
                "TwoFraudScore" => {
                    let u = u32::from(raw[current_byte]);
                    record.fraud_score.strictness[2] = Some(u);
                    value = u.to_string();
                    record.columns.push(Column {
                        name: column.name.clone(),
                        record_type: BinaryOption {
                            data: flag::SMALL_INT_DATA,
                        },
                        value,
                    });
                    current_byte += 1;
                }
                "ThreeFraudScore" => {
                    let u = u32::from(raw[current_byte]);
                    record.fraud_score.strictness[3] = Some(u);
                    value = u.to_string();
                    record.columns.push(Column {
                        name: column.name.clone(),
                        record_type: BinaryOption {
                            data: flag::SMALL_INT_DATA,
                        },
                        value,
                    });
                    current_byte += 1;
                }
                _ => {
                    let mut value = Default::default();
                    if column.record_type.has(flag::STRING_DATA) {
                        let offset = utility::four_byte_int(&raw[current_byte..current_byte + 4]);
                        value = FileReader::get_ranged_string_value(&mut file.reader, offset)?;
                        record.columns.push(Column {
                            name: column.name.clone(),
                            record_type: BinaryOption {
                                data: flag::STRING_DATA,
                            },
                            value: value.clone(),
                        });
                        current_byte += 4;
                    };
                    match column.name.as_str() {
                        "Country" => {
                            record.country = Some(value);
                        }
                        "City" => {
                            record.city = Some(value);
                        }
                        "Region" => {
                            record.region = Some(value);
                        }
                        "ISP" => {
                            record.isp = Some(value);
                        }
                        "Organization" => {
                            record.organization = Some(value);
                        }
                        "Timezone" => {
                            record.timezone = Some(value);
                        }
                        _ => {
                            return Err("failed to parse string data (EID 13)".into());
                        }
                    }
                }
            }
        }
        Ok(record)
    }

    pub fn is_proxy(&self) -> Option<bool> {
        self.is_proxy
    }

    pub fn is_vpn(&self) -> Option<bool> {
        self.is_vpn
    }

    pub fn is_tor(&self) -> Option<bool> {
        self.is_tor
    }

    pub fn is_crawler(&self) -> Option<bool> {
        self.is_crawler
    }

    pub fn is_bot(&self) -> Option<bool> {
        self.is_bot
    }

    pub fn recent_abuse(&self) -> Option<bool> {
        self.recent_abuse
    }

    pub fn is_blacklisted(&self) -> Option<bool> {
        self.is_blacklisted
    }

    pub fn is_private(&self) -> Option<bool> {
        self.is_private
    }

    pub fn is_mobile(&self) -> Option<bool> {
        self.is_mobile
    }

    pub fn has_open_ports(&self) -> Option<bool> {
        self.has_open_ports
    }

    pub fn is_hosting_provider(&self) -> Option<bool> {
        self.is_hosting_provider
    }

    pub fn active_vpn(&self) -> Option<bool> {
        self.active_vpn
    }

    pub fn active_tor(&self) -> Option<bool> {
        self.active_tor
    }

    pub fn public_access_point(&self) -> Option<bool> {
        self.public_access_point
    }

    pub fn connection_type(&self) -> &str {
        &self.connection_type
    }

    pub fn abuse_velocity(&self) -> &str {
        &self.abuse_velocity
    }

    pub fn country(&self) -> Option<&str> {
        if self.country.is_some() {
            return self.country.as_deref();
        }
        None
    }

    pub fn city(&self) -> Option<&str> {
        if self.city.is_some() {
            return self.city.as_deref();
        }
        None
    }

    pub fn region(&self) -> Option<&str> {
        if self.region.is_some() {
            return self.region.as_deref();
        }
        None
    }

    pub fn isp(&self) -> Option<&str> {
        if self.isp.is_some() {
            return self.isp.as_deref();
        }
        None
    }

    pub fn organization(&self) -> Option<&str> {
        if self.organization.is_some() {
            return self.organization.as_deref();
        }
        None
    }

    pub fn asn(&self) -> Option<u64> {
        self.asn
    }

    pub fn timezone(&self) -> Option<&str> {
        if self.timezone.is_some() {
            return self.timezone.as_deref();
        }
        None
    }

    pub fn latitude(&self) -> Option<f32> {
        self.latitude
    }

    pub fn longitude(&self) -> Option<f32> {
        self.longitude
    }

    pub fn fraud_score(&self, strictness: Strictness) -> Option<u32> {
        match strictness {
            Strictness::Zero => self.fraud_score.strictness[0],
            Strictness::One => self.fraud_score.strictness[1],
            Strictness::Two => self.fraud_score.strictness[2],
            Strictness::Three => self.fraud_score.strictness[3],
        }
    }
}

/// Returns one of: Residential, Mobile, Corporate, Data Center, Education, or Unknown
pub fn connection_type(byte: u8) -> &'static str {
    match byte & flag::CONNECTION_MASK {
        flag::CONNECTION_TYPE_THREE => "Residential", // 001
        flag::CONNECTION_TYPE_TWO => "Mobile",        // 010
        flag::THREE_UNION_TWO => "Corporate",         // 011
        flag::CONNECTION_TYPE_ONE => "Data Center",   // 100
        flag::THREE_UNION_ONE => "Education",         // 101
        _ => "Unknown",
    }
}

/// How frequently the IP address is engaging in abuse across the IPQS threat network.
/// Values can be "high", "medium", "low", or "none".
pub fn abuse_velocity(byte: u8) -> &'static str {
    match byte & flag::ABUSE_VELOCITY_MASK {
        flag::ABUSE_VELOCITY_TWO => "low",    // 01
        flag::ABUSE_VELOCITY_ONE => "medium", // 10
        flag::ABUSE_BOTH => "high",           // 11
        _ => "none",
    }
}

#[derive(Clone, Default, Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub(crate) struct FraudScore {
    pub strictness: [Option<u32>; 4],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_zero() {
        let c123: u8 = 0b1100_0000;
        let connection_type = connection_type(c123);
        assert_eq!(connection_type, "Unknown");
    }

    #[test]
    fn ct_three() {
        // 001
        let c123: u8 = 0b1110_0000;
        let connection_type = connection_type(c123);
        assert_eq!(connection_type, "Residential");
    }

    #[test]
    fn ct_two() {
        // 010
        let c123: u8 = 0b1101_0000;
        let connection_type = connection_type(c123);
        assert_eq!(connection_type, "Mobile");
    }

    #[test]
    fn ct_two_and_three() {
        // 011
        let c123: u8 = 0b1111_0000;
        println!("{}", c123);
        let connection_type = connection_type(c123);
        assert_eq!(connection_type, "Corporate");
    }

    #[test]
    fn ct_one() {
        // 100
        let c123: u8 = 0b1100_1000;
        let connection_type = connection_type(c123);
        assert_eq!(connection_type, "Data Center");
    }

    #[test]
    fn ct_one_and_three() {
        // 101
        let c123: u8 = 0b1110_1000;
        let connection_type = connection_type(c123);
        assert_eq!(connection_type, "Education");
    }

    #[test]
    fn ab_0() {
        let ab: u8 = 0b0011_1000;
        let abuse_velocity = abuse_velocity(ab);
        assert_eq!(abuse_velocity, "none");
    }

    #[test]
    fn ab_one() {
        // 10
        let ab: u8 = 0b0111_1000;
        let abuse_velocity = abuse_velocity(ab);
        assert_eq!(abuse_velocity, "medium");
    }

    #[test]
    fn ab_two() {
        // 01
        let ab: u8 = 0b1011_1000;
        let abuse_velocity = abuse_velocity(ab);
        assert_eq!(abuse_velocity, "low");
    }

    #[test]
    fn ab_one_and_two() {
        // 11
        let ab: u8 = 0b1111_1000;
        let abuse_velocity = abuse_velocity(ab);
        assert_eq!(abuse_velocity, "high");
    }
}
