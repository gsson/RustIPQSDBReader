// Copyright 2023 IPQualityScore LLC

pub const CONNECTION_MASK: u8 = 0b0011_1000; // mask three connection bits
pub const ABUSE_VELOCITY_MASK: u8 = 0b1100_0000; // mask two abuse velocity bits

// pub const RESERVED_ELEVEN: u8 = 0b0000_0001;
// pub const RESERVED_TWELVE: u8 = 0b0000_0010;
pub const TREE_DATA: u8 = 0b0000_0100;
pub const STRING_DATA: u8 = 0b0000_1000;
pub const SMALL_INT_DATA: u8 = 0b0001_0000;
pub const INT_DATA: u8 = 0b0010_0000;
pub const FLOAT_DATA: u8 = 0b0100_0000;
// pub const RESERVED_THIRTEEN: u8 = 0b1000_0000;

// byte 1
pub const IS_PROXY: u8 = 0x01;
pub const IS_VPN: u8 = 0x02;
pub const IS_TOR: u8 = 0x04;
pub const IS_CRAWLER: u8 = 0x08;
pub const IS_BOT: u8 = 0x10;
pub const RECENT_ABUSE: u8 = 0x20;
pub const IS_BLACKLISTED: u8 = 0x40;
pub const IS_PRIVATE: u8 = 0x80;

// byte 2;
pub const IS_MOBILE: u8 = 0x01;
pub const HAS_OPEN_PORTS: u8 = 0x02;
pub const IS_HOSTING_PROVIDER: u8 = 0x04;
pub const ACTIVE_VPN: u8 = 0x08;
pub const ACTIVE_TOR: u8 = 0x10;
pub const PUBLIC_ACCESS_POINT: u8 = 0x20;
// pub const RESERVED_ONE: u8 = 0x40;
// pub const RESERVED_TWO: u8 = 0x80;

// byte 3;
// pub const RESERVED_THREE: u8 = 0x01;
// pub const RESERVED_FOUR: u8 = 0x02;
// pub const RESERVED_FIVE: u8 = 0x04;
pub const CONNECTION_TYPE_ONE: u8 = 0x08;
pub const CONNECTION_TYPE_TWO: u8 = 0x10;
pub const CONNECTION_TYPE_THREE: u8 = 0x20;
pub const ABUSE_VELOCITY_ONE: u8 = 0x40;
pub const ABUSE_VELOCITY_TWO: u8 = 0x80;

// required because match only allows patterns, not expressions
pub const THREE_UNION_TWO: u8 = CONNECTION_TYPE_THREE | CONNECTION_TYPE_TWO;
pub const THREE_UNION_ONE: u8 = CONNECTION_TYPE_THREE | CONNECTION_TYPE_ONE;
pub const ABUSE_BOTH: u8 = ABUSE_VELOCITY_ONE | ABUSE_VELOCITY_TWO;

#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct BinaryOption {
    pub data: u8,
}

impl BinaryOption {
    pub fn has(&self, flag: u8) -> bool {
        self.data & flag != 0
    }
}
