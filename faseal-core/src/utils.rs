// FaSEAL, a simple tool for encrypted archives
// Copyright (C) 2025 A. Russon
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::io::{
    BufReader,
    Read
};
use faseal_crypto::hashes::sha3::Sha3_512;
use crate::errors::{
    Error,
    Result
};

pub(crate) fn read_buf_var<R: Read>(
    reader: &mut BufReader<R>,
    buf_len: &mut [u8; 8],
    max: usize
) -> Result<Vec<u8>> {
    reader.read_exact(buf_len)?;
    let length = u64::from_le_bytes(*buf_len) as usize;
    if length > max {
        return Err(Error::InvalidLength);
    }
    let mut buf = vec![0u8; length];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

pub(crate) fn gen_uuidv4_from_hash(h: &[u8; Sha3_512::HASH_LEN]) -> String {
    gen_uuidv4(h[..16].try_into().unwrap())
}

fn gen_uuidv4(mut buf: [u8; 16]) -> String {
    // xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx
    // M: 4 msb of 7th byte set to 0b0100 (version 4)
    // N: 2 msb of 9th byte set to 0b10 (variant)
    buf[6] = (buf[6] & 0xf) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;

    // safe since the output buffer has a fixed size of correct length
    let mut uuid = [b'-'; 36];
    hex::encode_to_slice(&buf[..4], &mut uuid[..8]).unwrap();
    hex::encode_to_slice(&buf[4..6], &mut uuid[9..13]).unwrap();
    hex::encode_to_slice(&buf[6..8], &mut uuid[14..18]).unwrap();
    hex::encode_to_slice(&buf[8..10], &mut uuid[19..23]).unwrap();
    hex::encode_to_slice(&buf[10..], &mut uuid[24..]).unwrap();

    // safe since it is a hexadecimal string
    unsafe { String::from_utf8_unchecked(uuid.to_vec()) }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::gen_uuidv4;

    #[test]
    fn test_uuid() {
        // example from https://datatracker.ietf.org/doc/html/rfc9562#appendix-A.3
        let buf = hex!("919108f752d133205bacf847db4148a8");
        let uuid = gen_uuidv4(buf);

        assert_eq!(uuid, "919108f7-52d1-4320-9bac-f847db4148a8");
    }
}
