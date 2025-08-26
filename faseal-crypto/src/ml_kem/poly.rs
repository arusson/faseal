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

use crate::{
    hashes::sha3::{
        Shake128,
        Shake256
    },
    ml_kem::{
        MLKEM_Q,
        MLKEM_Q32,
        fq::{
            fq_barrett_reduce,
            fq_mul,
            fq_simple_reduce
        }
    }
};

const KYBER_N: usize = 256;

// first table of FIPS 203 appendix A (coefficients centered on 0)
const ZETAS: [i16; 128] = [
    1,    -1600,  -749,   -40,  -687,   630, -1432,   848,
    1062, -1410,   193,   797,  -543,   -69,   569, -1583,
    296,   -882,  1339,  1476,  -283,    56, -1089,  1333,
    1426, -1235,   535,  -447,  -936,  -450, -1355,   821,
    289,    331,   -76, -1573,  1197, -1025, -1052, -1274,
    650,  -1352,  -816,   632,  -464,    33,  1320, -1414,
    -1010, 1435,   807,   452,  1438,  -461,  1534,  -927,
    -682,  -712,  1481,   648,  -855,  -219,  1227,   910,
    17,    -568,   583,  -680,  1637,   723, -1041,  1100,
    1409,  -667,   -48,   233,   756, -1173,  -314,  -279,
    -1626, 1651,  -540, -1540, -1482,   952,  1461,  -642,
    939,  -1021,  -892,  -941,   733,  -992,   268,   641,
    1584, -1031, -1292,  -109,   375,  -780, -1239,  1645,
    1063,   319,  -556,   757, -1230,   561,  -863,  -735,
    -525,  1092,   403,  1026,  1143, -1179,  -554,   886,
    -1607, 1212, -1455,  1029, -1219,  -394,   885, -1175,
];

#[derive(Clone)]
pub(crate) struct Poly(pub(crate) [i16; KYBER_N]);

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Poly {
    pub(crate) const LEN: usize = 384;
    const COMPRESSED_LEN: usize = 128;
    pub(crate) const ZERO: Self = Self([0; KYBER_N]);

    // FIPS 203, algorithm 7
    pub(crate) fn sample_ntt(input: &[u8; 32], i: u8, j: u8) -> Self {
        let mut xof = Shake128::init();
        xof.absorb(&[input, &[j, i]]);
        let mut buf = [0i16; KYBER_N];

        let mut j = 0;
        while j < KYBER_N {
            let mut c = [0u8; 3];
            xof.squeeze(&mut c);
            let d1 = (c[0] as i16) | (((c[1] & 0xf) as i16) << 8);
            let d2 = ((c[1] >> 4) as i16) | ((c[2] as i16) << 4);
            if d1 < MLKEM_Q {
                buf[j] = d1;
                j += 1;
            }
            if d2 < MLKEM_Q && j < KYBER_N {
                buf[j] = d2;
                j += 1;
            }
        }
        Self(buf)
    }

    // FIPS 203, algorithm 8
    pub(crate) fn sample_cbd(input: &[u8; 32], n: u8) -> Self {
        let mut buffer = [0u8; 128];
        Shake256::hash_into(&[input, &[n]], &mut buffer);
        let mut f = [0i16; KYBER_N];
        for (src, dst) in buffer.chunks_exact(8).zip(f.chunks_exact_mut(16)) {
            let t = u64::from_le_bytes(src.try_into().unwrap());
            let mut d = t & 0x55555555_55555555;
            d += (t >> 1) & 0x55555555_55555555;

            for (i, coef) in dst.iter_mut().enumerate() {
                let a = ((d >> (4 * i)) & 0x3) as i16;
                let b = ((d >> (4 * i +  2)) & 0x3) as i16;
                *coef = a - b;
            }
        }
        buffer.zeroize();
        Self(f)
    }

    // FIPS 203, algorithm 9
    // All coefficients are reduced in [-1664, 1664].
    pub(crate) fn ntt(&mut self) {
        let mut k = 1;
        for len in [128, 64, 32, 16, 8, 4, 2] {
            for start in (0..256).step_by(2 * len) {
                let zeta = ZETAS[k];
                k += 1;
                for j in start..(start + len) {
                    let t = fq_mul(zeta, self.0[j + len]);
                    self.0[j + len] = fq_simple_reduce(self.0[j] - t);
                    self.0[j] = fq_simple_reduce(self.0[j] + t);
                }
            }
        }
    }

    // FIPS 203, algorithm 10
    pub(crate) fn inv_ntt(&mut self) {
        const F: i16 = -26;
        let mut k = 127;
        for len in [2, 4, 8, 16, 32, 64, 128] {
            for start in (0..256).step_by(2 * len) {
                let zeta = ZETAS[k];
                k -= 1;
                for j in start..(start + len) {
                    let t = self.0[j];
                    self.0[j] = fq_simple_reduce(t + self.0[j + len]);
                    self.0[j + len] -= t;
                    self.0[j + len] = fq_mul(zeta, self.0[j + len]);
                }
            }
        }
        for coef in self.0.iter_mut() {
            *coef = fq_mul(*coef, F);
        }
    }

    // Add operand to self.
    // Does not reduce coefficients.
    pub(crate) fn radd(&mut self, rhs: &Self) {
        for (rc, &ac) in self.0.iter_mut().zip(rhs.0.iter()) {
            *rc += ac;
        }
    }

    // Subtract self from operand.
    // Does not reduce coefficients.
    pub(crate) fn lsub(&mut self, lhs: &Self) {
        for (rc, &ac) in self.0.iter_mut().zip(lhs.0.iter()) {
            *rc = ac - *rc;
        }
    }

    // Barrett reduction is sufficient here: in all cases, coefficients stay within bounds
    // such that Barrett reduction results with values in [-1664, 1664].
    pub(crate) fn reduce(&mut self) {
        for coef in self.0.iter_mut() {
            *coef = fq_barrett_reduce(*coef as i32);
        }
    }

    // FIPS 203, algorithms 11 and 12
    // Coefficients might not be reduced but stay within [-(q-1), q-1].
    pub(crate) fn mul(&self, rhs: &Self) -> Self {
        let mut r = Self::ZERO;
        macro_rules! basemul {
            ($i:expr, $zeta:expr) => {
                r.0[$i]      = fq_mul(self.0[$i + 1], rhs.0[$i + 1]);
                r.0[$i]      = fq_mul(r.0[$i],        $zeta);
                r.0[$i]     += fq_mul(self.0[$i],     rhs.0[$i]);
                r.0[$i + 1]  = fq_mul(self.0[$i],     rhs.0[$i + 1]);
                r.0[$i + 1] += fq_mul(self.0[$i + 1], rhs.0[$i]);
            };
        }
    
        for (i, &zeta) in (0..KYBER_N).step_by(4).zip(ZETAS[64..].iter()) {
            basemul!(i, zeta);
            basemul!(i + 2, -(zeta));
        }
        r
    }

    pub(crate) fn pack_bytes(&self, buffer: &mut [u8; Self::LEN]) {
        for (src, dst) in self.0.chunks_exact(2).zip(buffer.chunks_exact_mut(3)) {
            let t0 = (src[0] + ((src[0] >> 15) & MLKEM_Q)) as u16;
            let t1 = (src[1] + ((src[1] >> 15) & MLKEM_Q)) as u16;
            dst[0] =   t0 as u8;
            dst[1] = ((t0 >> 8) | (t1 << 4)) as u8;
            dst[2] =  (t1 >> 4) as u8;
        }
    }

    pub(crate) fn from_bytes(buffer: &[u8; Self::LEN]) -> Self {
        let mut poly = Self::ZERO;
        for (src, dst) in buffer.chunks_exact(3).zip(poly.0.chunks_exact_mut(2)) {
            dst[0] = (src[0] as i16) | (((src[1] & 0xf) as i16) << 8);
            dst[1] = ((src[1] as i16) >> 4) | ((src[2] as i16) << 4);
        }
        poly
    }

    pub(crate) fn from_msg(msg: &[u8; 32]) -> Self {
        let mut poly = Self::ZERO;
        for (&byte, coefs) in msg.iter().zip(poly.0.chunks_exact_mut(8)) {
            for (j, coef) in coefs.iter_mut().enumerate() {
                let bit = -(((byte >> j) & 1) as i16);
                *coef ^= bit & ((*coef) ^ 1665);
            }
        }
        poly
    }

    pub(crate) fn to_msg(&self) -> [u8; 32] {
        let mut msg = [0u8; 32];
        for (m, coefs) in msg.iter_mut().zip(self.0.chunks_exact(8)) {
            for (j, &coef) in coefs.iter().enumerate() {
                let mut t = (coef as u32) << 1;
                t = t.wrapping_add(1665);
                t = t.wrapping_mul(80_635);
                t >>= 28;
                t &= 1;
                *m |= (t << j) as u8;
            }
        }
        msg
    }

    pub(crate) fn compress(&self, buffer: &mut [u8; Self::COMPRESSED_LEN]) {
        for (coefs, dst) in self.0.chunks_exact(8).zip(buffer.chunks_exact_mut(4)) {
            let mut t = [0u8; 8];
            for (tt, &coef) in t.iter_mut().zip(coefs.iter()) {
                let u = coef + ((coef >> 15) & MLKEM_Q);
                let mut d0 = (u as u32) << 4;
                d0 += 1665;
                d0 = d0.wrapping_mul(80_635);
                d0 >>= 28;
                *tt = (d0 & 0xf) as u8;
            }

            dst[0] = t[0] | (t[1] << 4);
            dst[1] = t[2] | (t[3] << 4);
            dst[2] = t[4] | (t[5] << 4);
            dst[3] = t[6] | (t[7] << 4);
        }
    }

    pub(crate) fn decompress(buffer: &[u8; Self::COMPRESSED_LEN]) -> Self {
        let mut poly = Self::ZERO;
        for (coefs, &src) in poly.0.chunks_exact_mut(2).zip(buffer.iter()) {
            coefs[0] = ((((src & 0xf) as i32) * MLKEM_Q32 + 8) >> 4) as i16;
            coefs[1] = ((((src >> 4) as i32) * MLKEM_Q32 + 8) >> 4) as i16;
        }
        poly
    }
}

#[cfg(test)]
mod tests {
    use super::Poly;
    use rand::RngCore;

    #[test]
    fn test_ml_kem_pack_msg() {
        let mut msg1 = [0u8; 32];
        rand::rng().fill_bytes(&mut msg1);
        let poly = Poly::from_msg(&msg1);
        let msg2 = poly.to_msg();
        assert_eq!(msg1, msg2);
    }

    #[test]
    fn test_ml_kem_poly_compress() {
        let mut buf1 = [0u8; Poly::COMPRESSED_LEN];
        rand::rng().fill_bytes(&mut buf1);
        let poly = Poly::decompress(&buf1);
        let mut buf2 = [0u8; Poly::COMPRESSED_LEN];
        poly.compress(&mut buf2);
        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_ml_kem_poly_pack() {
        let mut buf1 = [0u8; Poly::LEN];
        rand::rng().fill_bytes(&mut buf1);
        let poly = Poly::from_bytes(&buf1);
        let mut buf2 = [0u8; Poly::LEN];
        poly.pack_bytes(&mut buf2);
        assert_eq!(buf1, buf2);
    }
}
