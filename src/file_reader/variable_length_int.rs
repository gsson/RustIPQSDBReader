// Copyright 2023 IPQualityScore LLC

// This is a minimal reimplementation (from scratch) of Go's binary.Uvarint
// That source available here: https://cs.opensource.google/go/go/+/refs/tags/go1.20.3:src/encoding/binary/varint.go;l=69
// and available under a modified BSD license: https://go.dev/LICENSE?m=text
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::error::Error;

const MAX_VAR_INT_LEN_64: usize = 10;

/// takes a slice of bytes encoded according to [Base 128 Varints](https://protobuf.dev/programming-guides/encoding/#varints)
/// and returns either the decoded u64 integer or an error
pub fn uvarint64(bytes: &[u8]) -> Result<u64, Box<dyn Error>> {
    if bytes.len() > MAX_VAR_INT_LEN_64 {
        return Err("catch byte reads past MaxVarIntLen64".into()); // overflow
    }
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if *byte < 0x80 {
            // 128, or 1000 0000
            if (i == MAX_VAR_INT_LEN_64 - 1) && (*byte > 1) {
                return Err("overflow".into());
            }
            x |= (*byte as u64) << s;
            break;
        }
        x |= ((*byte & 0x7f) as u64) << s; // 127, or 0111 1111
        s += 7;
    }

    Ok(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() -> Result<(), Box<dyn Error>> {
        let bytes: [u8; 3] = [0x93, 0x02, 0x00];
        let answer = uvarint64(&bytes)?;
        assert_eq!(answer, 275);

        Ok(())
    }

    #[test]
    fn long_read() -> Result<(), Box<dyn Error>> {
        // Reading should stop after the first non-continuation byte
        let bytes: [u8; 3] = [0x93, 0x02, 0x01];
        let answer = uvarint64(&bytes)?;
        assert_eq!(answer, 275);

        Ok(())
    }

    #[test]
    fn too_long() {
        let l = [11; 0xff];
        let x = uvarint64(&l);
        assert!(x.is_err());
    }
}
