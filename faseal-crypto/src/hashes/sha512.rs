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

// adapated from https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c

use zeroize::Zeroize;

const HASH_LEN: usize = 64;

const SHA512_INIT_STATE: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
];

const KRND: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

const PAD: [u8; 128] = [
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0
];

macro_rules! Ch {
    ($x:expr, $y:expr, $z:expr) => {
        (($x & ($y ^ $z)) ^ $z)
    };
}

macro_rules! Maj {
    ($x:expr, $y:expr, $z:expr) => {
        (($x & ($y | $z)) | ($y & $z))
    };
}

macro_rules! S0 {
    ($x:expr) => {
        ($x.rotate_right(28) ^ $x.rotate_right(34) ^ $x.rotate_right(39))
    };
}

macro_rules! S1 {
    ($x:expr) => {
        ($x.rotate_right(14) ^ $x.rotate_right(18) ^ $x.rotate_right(41))
    };
}

macro_rules! s0 {
    ($x:expr) => {
        ($x.rotate_right(1) ^ $x.rotate_right(8) ^ ($x >> 7))
    };
}

macro_rules! s1 {
    ($x:expr) => {
        ($x.rotate_right(19) ^ $x.rotate_right(61) ^ ($x >> 6))
    };
}

macro_rules! RND {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $k:expr) => {
        $h = $h.wrapping_add(S1!($e).wrapping_add(Ch!($e, $f, $g).wrapping_add($k)));
        $d = $d.wrapping_add($h);
        $h = $h.wrapping_add(S0!($a).wrapping_add(Maj!($a, $b, $c)));
    };
}

fn tranform(state: &mut [u64; 8], block: &[u8; 128], w: &mut [u64; 80], s: &mut [u64; 8]) {
    for (dst, src) in w.iter_mut().zip(block.chunks_exact(8)) {
        *dst = u64::from_be_bytes(src.try_into().unwrap());
    }

    *s = *state;
    for i in (0..80).step_by(16) {

        for j in 0..16 {
            RND!(s[(80 - j) % 8], s[(81 - j) % 8],
                 s[(82 - j) % 8], s[(83 - j) % 8],
                 s[(84 - j) % 8], s[(85 - j) % 8],
                 s[(86 - j) % 8], s[(87 - j) % 8],
                 w[i + j].wrapping_add(KRND[i + j]));
        }

        if i == 64 {
            break;
        }

        for j in 0..16 {
            w[i + j + 16] = s1!(w[i + j + 14])
                .wrapping_add(w[i + j + 9]
                .wrapping_add(s0!(w[i + j + 1])
                .wrapping_add(w[i + j])));
        }
    }
    for i in 0..8 {
        state[i] = state[i].wrapping_add(s[i]);
    }
}

pub(crate) struct Sha512 {
    count: [u64; 2],
    state: [u64; 8],
    buf: [u8; 128]
}

impl Sha512 {
    pub(crate) fn init() -> Self {
        Self {
            count: [0; 2],
            state: SHA512_INIT_STATE,
            buf: [0u8; 128]
        }
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        let mut tmp64_1 = [0u64; 80];
        let mut tmp64_2 = [0u64; 8];
        let mut bitlen = [0u64; 2];

        let r = ((self.count[1] >> 3) & 0x7f) as usize;
        bitlen[1] = (input.len() << 3) as u64;
        bitlen[0] = (input.len() >> 61) as u64;

        self.count[1] += bitlen[1];
        if self.count[1] < bitlen[1] {
            self.count[0] += 1;
        }

        self.count[0] += bitlen[0];
        if input.len() < 128 - r {
            self.buf[r..(r + input.len())].copy_from_slice(input);
            return;
        }
        self.buf[r..128].copy_from_slice(&input[..(128 - r)]);

        tranform(&mut self.state, &self.buf, &mut tmp64_1, &mut tmp64_2);

        for block in input[(128 - r)..].chunks_exact(128) {
            tranform(&mut self.state, block.try_into().unwrap(), &mut tmp64_1, &mut tmp64_2);
        }

        let lastlen = (input.len() - (128 - r)) % 128;
        self.buf[..lastlen].copy_from_slice(&input[(input.len()-lastlen)..]);

        tmp64_1.zeroize();
        tmp64_2.zeroize();
    }

    pub(crate) fn finalize(&mut self) -> [u8; HASH_LEN] {
        let mut tmp64_1 = [0u64; 80];
        let mut tmp64_2 = [0u64; 8];
    
        let r = ((self.count[1] >> 3) & 0x7f) as usize;
        if r < 112 {
            self.buf[r..112].copy_from_slice(&PAD[..(112 - r)]);
        
        }
        else {
            self.buf[r..].copy_from_slice(&PAD[..(128 - r)]);
            tranform(&mut self.state, &self.buf, &mut tmp64_1, &mut tmp64_2);
            self.buf[..112].zeroize();
        }
        self.buf[112..120].copy_from_slice(&u64::to_be_bytes(self.count[0]));
        self.buf[120..128].copy_from_slice(&u64::to_be_bytes(self.count[1]));
        tranform(&mut self.state, &self.buf, &mut tmp64_1, &mut tmp64_2);

        let mut out = [0u8; 64];
        for (dst, &src) in out.chunks_exact_mut(8).zip(self.state.iter()) {
            dst.copy_from_slice(&u64::to_be_bytes(src));
        }

        tmp64_1.zeroize();
        tmp64_2.zeroize();
        out
    }

    pub(crate) fn hash(input: &[u8]) -> [u8; HASH_LEN] {
        let mut sha = Sha512::init();
        sha.update(input);
        sha.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::Sha512;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Lines};

    // using byte-oriented test vectors from:
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing

    fn load_value(lines: &mut Lines<BufReader<File>>, prefix: &str) -> Option<Vec<u8>> {
        for line in lines.by_ref() {
            let Ok(line) = line else {
                return None
            };
            if !line.starts_with(prefix) {
                continue;
            }
            let (_, val_str) = line.split_at(prefix.len());
            return hex::decode(val_str.trim()).ok()
        }
        None
    }

    // message length is in bits
    fn load_len(lines: &mut Lines<BufReader<File>>) -> Option<usize> {
        for line in lines.by_ref() {
            let Ok(line) = line else { return None };
            if line.starts_with("Len = ") {
                let (_, val_str) = line.split_at(6);
                return val_str.parse::<usize>().ok();
            }
            else if line.starts_with("Outputlen = ") {
                let (_, val_str) = line.split_at(12);
                return val_str.parse::<usize>().ok()
            }
        }
        None
    }

    fn test_sha_512(fname: &str, expected_count: usize) {
        let file = File::open(fname).unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(len) = load_len(&mut lines) {
            dbg!(count);
            let Some(message) = load_value(&mut lines, "Msg = ") else { break };
            let Some(expected) = load_value(&mut lines, "MD = ") else { break };
            let hash = match len {
                0 => {
                    assert_eq!(message, [0]);
                    Sha512::hash(b"")
                }
                _ => {
                    assert_eq!(message.len(), len / 8);
                    Sha512::hash(&message)
                }
            };
            assert_eq!(hash.as_ref(), expected);

            count += 1;
        }
        assert_eq!(count, expected_count);
    }

    #[test]
    fn test_sha_512_long() {
        test_sha_512("tests/SHA512LongMsg.rsp", 128);
    }

    #[test]
    fn test_sha_512_short() {
        test_sha_512("tests/SHA512ShortMsg.rsp", 129);
    }
}
