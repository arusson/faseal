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

struct Blake2bCore {
    b: [u8; 128],
    h: [u64; 8],
    t: [u64; 2],
    c: u64,
}

pub(crate) struct Blake2b<const SIZE: usize>(Blake2bCore);
pub(crate) type Blake2b512 = Blake2b<64>;
pub(crate) type Blake2b256 = Blake2b<32>;

const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
];

impl Blake2bCore {
    fn update(&mut self, input: &[u8]) {
        for &byte in input {
            if self.c == 128 {
                self.t[0] = self.t[0].wrapping_add(self.c);
                if self.t[0] < self.c {
                    self.t[1] += 1;
                }
                self.compress(false);
                self.c = 0;
            }
            self.b[self.c as usize] = byte;
            self.c += 1;
        }
    }

    fn compress(&mut self, last: bool) {    
        const SIGMA: [[usize; 16]; 12] = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
            [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
            [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
            [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
            [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
            [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
            [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
            [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
            [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
        ];

        let mut v = [0u64; 16];
        v[0..8].copy_from_slice(&self.h);
        v[8..16].copy_from_slice(&BLAKE2B_IV);
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        if last {
            v[14] = !v[14];
        }
 
        let mut m = [0u64; 16];
        for (dst, src) in m.iter_mut().zip(self.b.chunks_exact(8)) {
            *dst = u64::from_le_bytes(src.try_into().unwrap());
        }
 
        macro_rules! quarter_round {
            ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $y:expr) => {
                v[$a] = v[$a].wrapping_add($x);
                v[$a] = v[$a].wrapping_add(v[$b]);
                v[$d] ^= v[$a];
                v[$d] = v[$d].rotate_right(32);
                
                v[$c] = v[$c].wrapping_add(v[$d]);
                v[$b] ^= v[$c];
                v[$b] = v[$b].rotate_right(24);
                
                v[$a] = v[$a].wrapping_add($y);
                v[$a] = v[$a].wrapping_add(v[$b]);
                v[$d] ^= v[$a];
                v[$d] = v[$d].rotate_right(16);
                
                v[$c] = v[$c].wrapping_add(v[$d]);
                v[$b] ^= v[$c];
                v[$b] = v[$b].rotate_right(63);
            };
        }
        
        for i in 0..12 {
            quarter_round!(0, 4,  8, 12, m[SIGMA[i][ 0]], m[SIGMA[i][ 1]]);
            quarter_round!(1, 5,  9, 13, m[SIGMA[i][ 2]], m[SIGMA[i][ 3]]);
            quarter_round!(2, 6, 10, 14, m[SIGMA[i][ 4]], m[SIGMA[i][ 5]]);
            quarter_round!(3, 7, 11, 15, m[SIGMA[i][ 6]], m[SIGMA[i][ 7]]);
            quarter_round!(0, 5, 10, 15, m[SIGMA[i][ 8]], m[SIGMA[i][ 9]]);
            quarter_round!(1, 6, 11, 12, m[SIGMA[i][10]], m[SIGMA[i][11]]);
            quarter_round!(2, 7,  8, 13, m[SIGMA[i][12]], m[SIGMA[i][13]]);
            quarter_round!(3, 4,  9, 14, m[SIGMA[i][14]], m[SIGMA[i][15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    fn finalize(&mut self, out: &mut [u8]) {
        self.t[0] = self.t[0].wrapping_add(self.c);
        if self.t[0] < self.c {
            self.t[1] += 1;
        }

        while self.c < 128 {
            self.b[self.c as usize] = 0;
            self.c += 1;
        }
        self.compress(true);

        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (self.h[i >> 3] >> (8 * (i & 7))) as u8;
        }
    }
}

impl<const SIZE: usize> Blake2b<SIZE> {
    pub(crate) fn init() -> Self {
        let mut core = Blake2bCore {
            b: [0u8; 128],
            h: BLAKE2B_IV,
            t: [0u64; 2],
            c: 0,
        };
        core.h[0] ^= 0x01010000 ^ SIZE as u64;
        Self(core)
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        self.0.update(input)
    }

    pub(crate) fn finalize(&mut self) -> [u8; SIZE] {
        let mut out = [0u8; SIZE];
        self.0.finalize(&mut out);
        out
    }

    pub(crate) fn hash(input: &[u8]) -> [u8; SIZE] {
        let mut blake = Self::init();
        blake.0.update(input);
        let mut out = [0u8; SIZE];
        blake.0.finalize(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Lines};
    use super::Blake2b512;

    // loads next line of hex data with a specific prefix
    fn load_value(lines: &mut Lines<BufReader<File>>, prefix: &str) -> Option<Vec<u8>> {
        for line in lines.by_ref() {
            let Ok(line) = line else { return None };
            if !line.starts_with(prefix) {
                continue;
            }
            let (_, val_str) = line.split_at(prefix.len());
            return hex::decode(val_str.trim()).ok()
        }
        None
    }

    #[test]
    fn test_blake2_kat_no_key() {
        // source: https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json
        // ("hash": "blake2b" and "key": "")
        let file = File::open("tests/blake2b-kat.txt").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(input) = load_value(&mut lines, "in:") {
            let Some(expected) = load_value(&mut lines, "hash:") else { break };

            let h1 = Blake2b512::hash(&input);
            let mut blake = Blake2b512::init();
            blake.update(&input);
            let h2 = blake.finalize();

            assert_eq!(h1.as_ref(), expected);
            assert_eq!(h1, h2);
            count += 1;
        }

        assert_eq!(count, 256);
    }
}
