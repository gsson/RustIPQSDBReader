// Copyright 2023 IPQualityScore LLC

use crate::binary_option::BinaryOption;

// Copyright 2023 IPQualityScore LLC
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct Column {
    pub name: String,
    pub record_type: BinaryOption,
    pub value: String,
}
