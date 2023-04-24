// Copyright 2023 IPQualityScore LLC

use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
};

use ipqs_db_reader::{FileReader, Strictness};

const IPV4_EXAMPLE: &str = "8.8.0.0";
const IPV6_EXAMPLE: &str = "2001:4860:4860::8844";

#[test]
fn ipv6() -> Result<(), Box<dyn Error>> {
    let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv6.ipqs");
    let mut reader = FileReader::open(&path_buf)?;
    let ip: IpAddr = IpAddr::V6(Ipv6Addr::from_str(IPV6_EXAMPLE)?);
    let _ = reader.fetch(&ip)?;

    Ok(())
}

#[test]
fn specific_details() {
    let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");
    let mut reader = FileReader::open(&path_buf).unwrap();
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::from_str(IPV4_EXAMPLE).unwrap());
    let record = reader.fetch(&ip).unwrap();
    assert_eq!(record.is_proxy(), Some(true));
    assert_eq!(record.is_vpn(), Some(true));
    assert_eq!(record.is_tor(), Some(false));
    assert_eq!(record.is_crawler(), Some(false));
    assert_eq!(record.is_bot(), Some(false));
    assert_eq!(record.recent_abuse(), Some(false));
    assert_eq!(record.is_blacklisted(), Some(false));
    assert_eq!(record.is_private(), Some(false));
    assert_eq!(record.is_mobile(), Some(false));
    assert_eq!(record.has_open_ports(), Some(false));
    assert_eq!(record.is_hosting_provider(), Some(false));
    assert_eq!(record.active_vpn(), Some(false));
    assert_eq!(record.active_tor(), Some(false));
    assert_eq!(record.public_access_point(), Some(true));
    assert_eq!(record.connection_type(), "Corporate");
    assert_eq!(record.abuse_velocity(), "none");
    assert_eq!(record.country(), Some("US"));
    assert_eq!(record.city(), Some("Monroe"));
    assert_eq!(record.region(), Some("Louisiana"));
    assert_eq!(record.isp(), Some("Level 3 Communications"));
    assert_eq!(record.organization(), Some("Level 3 Communications"));
    assert_eq!(record.asn(), Some(3356));
    assert_eq!(record.timezone(), Some("America/Chicago"));
    assert_eq!(record.latitude(), Some(32.51));
    assert_eq!(record.longitude(), Some(-92.12));
    assert_eq!(record.fraud_score(Strictness::Zero), Some(75));
    assert_eq!(record.fraud_score(Strictness::One), Some(75));
}
