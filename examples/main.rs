// Copyright 2023 IPQuality Score LLC
use ipqs_db_reader::{FileReader, Strictness};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //----------------------
    //--------- IPv4--------
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::from_str("8.8.0.0").unwrap());

    let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");

    let mut reader = FileReader::open(&path_buf)?;
    let record = reader.fetch(&ip)?;

    if let Some(is_proxy) = record.is_proxy() {
        if is_proxy {
            println!("{} is a proxy!", ip);
        }
    }

    println!("Connection type: {}", record.connection_type());
    if let Some(fraud_score) = record.fraud_score(Strictness::Zero) {
        println!("Fraud Score (Strictness 0): {:#?}", fraud_score);
    }

    // Record implements fmt::Display
    println!("{}", record);

    // Record implements serde::Serialization
    #[cfg(feature = "json")]
    {
        let serialized = serde_json::to_string_pretty(&record)?;
        println!("{}", serialized);
    }

    // Record implements Clone
    let _ = record;

    //----------------------
    //--------- IPv6--------
    let ip: IpAddr = IpAddr::V6(Ipv6Addr::from_str("2001:4860:4860::8844").unwrap());

    let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv6.ipqs");

    let mut reader = FileReader::open(&path_buf)?;
    let record = reader.fetch(&ip)?;

    #[cfg(feature = "json")]
    {
        let serialized = serde_json::to_string_pretty(&record)?;
        println!("{}", serialized);
    }

    Ok(())
}
