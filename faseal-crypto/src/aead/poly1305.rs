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

use zeroize::Zeroize;

fn clamp(r: &mut [u64; 5]) {
    r[0] &= 0x0fff_ffff;
    r[1] &= 0x0fff_fffc;
    r[2] &= 0x0fff_fffc;
    r[3] &= 0x0fff_fffc;
}

fn add(a: &mut [u64; 5], b: &[u64; 5]) {
    let d0 = a[0] + b[0];
    let d1 = a[1] + b[1] + (d0 >> 32);
    let d2 = a[2] + b[2] + (d1 >> 32);
    let d3 = a[3] + b[3] + (d2 >> 32);
    a[0] = d0 & 0xffff_ffff;
    a[1] = d1 & 0xffff_ffff;
    a[2] = d2 & 0xffff_ffff;
    a[3] = d3 & 0xffff_ffff;
    a[4] += (d3 >> 32) + b[4];
}

fn mulmod1305(acc: &mut [u64; 5], r: &[u64; 5], rs: &[u64; 3]) {
    let mut d0 = acc[0]*r[0] + acc[1]*rs[2] + acc[2]*rs[1] + acc[3]*rs[0];
    let mut d1 = acc[0]*r[1] + acc[1]*r[0]  + acc[2]*rs[2] + acc[3]*rs[1] + acc[4]*rs[0];
    let mut d2 = acc[0]*r[2] + acc[1]*r[1]  + acc[2]*r[0]  + acc[3]*rs[2] + acc[4]*rs[1];
    let mut d3 = acc[0]*r[3] + acc[1]*r[2]  + acc[2]*r[1]  + acc[3]*r[0]  + acc[4]*rs[2];
    acc[4] *= r[0];

    // modular reduction by p = 2^130 - 5
    d1 += d0 >> 32;
    d2 += d1 >> 32;
    d3 += d2 >> 32;
    acc[0] = d0 & 0xffff_ffff;
    acc[1] = d1 & 0xffff_ffff;
    acc[2] = d2 & 0xffff_ffff;
    acc[3] = d3 & 0xffff_ffff;
    acc[4] += d3 >> 32;

    d0 = acc[0] + (acc[4] >> 2) + (acc[4] & 0xffff_fffc);
    acc[4] &= 3;
    acc[0] = d0 & 0xffff_ffff;
    d0 = acc[1] + (d0 >> 32);
    acc[1] = d0 & 0xffff_ffff;
    d0 = acc[2] + (d0 >> 32);
    acc[2] = d0 & 0xffff_ffff;
    d0 = acc[3] + (d0 >> 32);
    acc[3] = d0 & 0xffff_ffff;
    d0 = acc[4] + (d0 >> 32);
    acc[4] = d0 & 0xffff_ffff;
}

pub(crate) struct Poly1305 {
    r: [u64; 5],
    s: [u64; 5],
    rs: [u64; 3],
    acc: [u64; 5],
    finished: bool,
    tag: [u8; 16]
}

impl Poly1305 {
    pub(crate) const KEY_LENGTH: usize = 32;
    pub(crate) const TAG_LENGTH: usize = 16;

    pub(crate) fn new(key: &[u8; Self::KEY_LENGTH]) -> Poly1305 {
        let mut r = [0u64; 5];
        let mut s = [0u64; 5];
        let mut rs = [0u64; 3];

        r[0] = u32::from_le_bytes(key[..4].try_into().unwrap()) as u64;
        r[1] = u32::from_le_bytes(key[4..8].try_into().unwrap()) as u64;
        r[2] = u32::from_le_bytes(key[8..12].try_into().unwrap()) as u64;
        r[3] = u32::from_le_bytes(key[12..16].try_into().unwrap()) as u64;
        clamp(&mut r);

        rs[0] = r[1] + (r[1] >> 2);
        rs[1] = r[2] + (r[2] >> 2);
        rs[2] = r[3] + (r[3] >> 2);

        s[0] = u32::from_le_bytes(key[16..20].try_into().unwrap()) as u64;
        s[1] = u32::from_le_bytes(key[20..24].try_into().unwrap()) as u64;
        s[2] = u32::from_le_bytes(key[24..28].try_into().unwrap()) as u64;
        s[3] = u32::from_le_bytes(key[28..32].try_into().unwrap()) as u64;
        
        Self {
            r, s, rs, acc: [0u64; 5], finished: false, tag: [0u8; 16]
        }
    }

    pub(crate) fn update_padded(&mut self, msg: &[u8]) {
        let mut n = [0u64; 5];
        let mut blocks = msg.chunks_exact(16);
        for block in blocks.by_ref() {
            n[0] = u32::from_le_bytes(block[..4].try_into().unwrap()) as u64;
            n[1] = u32::from_le_bytes(block[4..8].try_into().unwrap()) as u64;
            n[2] = u32::from_le_bytes(block[8..12].try_into().unwrap()) as u64;
            n[3] = u32::from_le_bytes(block[12..16].try_into().unwrap()) as u64;
            n[4] = 1;
            add(&mut self.acc, &n);
            mulmod1305(&mut self.acc, &self.r, &self.rs);
        }

        let rem = blocks.remainder();
        if !rem.is_empty() {
            let mut block = [0u8; 16];
            block[..rem.len()].copy_from_slice(rem);
            n[0] = u32::from_le_bytes(block[..4].try_into().unwrap()) as u64;
            n[1] = u32::from_le_bytes(block[4..8].try_into().unwrap()) as u64;
            n[2] = u32::from_le_bytes(block[8..12].try_into().unwrap()) as u64;
            n[3] = u32::from_le_bytes(block[12..16].try_into().unwrap()) as u64;
            n[4] = 1;
            add(&mut self.acc, &n);
            mulmod1305(&mut self.acc, &self.r, &self.rs);
        }
    }

    pub(crate) fn update(&mut self, msg: &[u8]) {
        let mut n = [0u64; 5];
        let mut blocks = msg.chunks_exact(16);

        for block in blocks.by_ref() {
            n[0] = u32::from_le_bytes(block[..4].try_into().unwrap()) as u64;
            n[1] = u32::from_le_bytes(block[4..8].try_into().unwrap()) as u64;
            n[2] = u32::from_le_bytes(block[8..12].try_into().unwrap()) as u64;
            n[3] = u32::from_le_bytes(block[12..16].try_into().unwrap()) as u64;
            n[4] = 1;
            add(&mut self.acc, &n);
            mulmod1305(&mut self.acc, &self.r, &self.rs);
        }
    
        let rem = blocks.remainder();
        if !rem.is_empty() {
            let mut block = [0u8; 16];
            block[..rem.len()].copy_from_slice(rem);
            block[rem.len()] = 1;
            n[0] = u32::from_le_bytes(block[..4].try_into().unwrap()) as u64;
            n[1] = u32::from_le_bytes(block[4..8].try_into().unwrap()) as u64;
            n[2] = u32::from_le_bytes(block[8..12].try_into().unwrap()) as u64;
            n[3] = u32::from_le_bytes(block[12..16].try_into().unwrap()) as u64;
            n[4] = 0;
            add(&mut self.acc, &n);
            mulmod1305(&mut self.acc, &self.r, &self.rs);
        }
    }

    pub(crate) fn digest(&mut self) -> [u8; Self::TAG_LENGTH] {
        match self.finished {
            true => self.tag,
            false => {
                add(&mut self.acc, &self.s);
                for (t, a) in self.tag.chunks_exact_mut(4).zip(self.acc.iter()) {
                    t.copy_from_slice(&a.to_le_bytes()[..4]);
                }
                self.finished = true;
                self.tag
            }
        }
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
        self.rs.zeroize();
        self.acc.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::Poly1305;

    #[test]
    fn test_poly1305_1() {
        // source: https://datatracker.ietf.org/doc/html/rfc7539#section-2.5.2
        let message = b"Cryptographic Forum Research Group";
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
        ];
        let expected_tag: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
        ];

        let mut poly = Poly1305::new(&key);
        poly.update(message);
        let tag = poly.digest();
        assert_eq!(tag, expected_tag);
    }

    #[test]
    fn test_poly1305_2() {
        // source: https://datatracker.ietf.org/doc/html/rfc7539#section-2.8.2
        let message: [u8; 160] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7, 0x00, 0x00, 0x00, 0x00,
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
            0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
            0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
            0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
            0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
            0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
            0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
            0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
            0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
            0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
            0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
            0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
            0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let key: [u8; 32] = [
            0x7b, 0xac, 0x2b, 0x25, 0x2d, 0xb4, 0x47, 0xaf,
            0x09, 0xb6, 0x7a, 0x55, 0xa4, 0xe9, 0x55, 0x84,
            0x0a, 0xe1, 0xd6, 0x73, 0x10, 0x75, 0xd9, 0xeb,
            0x2a, 0x93, 0x75, 0x78, 0x3e, 0xd5, 0x53, 0xff
        ];
        let mut poly = Poly1305::new(&key);
        poly.update(&message);
        let tag = poly.digest();
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
            0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
        ];
        assert_eq!(tag, expected_tag);
    }
}
