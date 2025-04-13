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
        KYBER_Q,
        KYBER_Q32
    }
};

const KYBER_N: usize = 256;
const QINV: i16 = -3327; // q^-1 mod 2^16
const ZETAS: [i16; 128] = [
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
    -171,    622,  1577,   182,   962, -1202, -1474,  1468,
    573,   -1325,   264,   383,  -829,  1458, -1602,  -130,
    -681,   1017,   732,   608, -1542,   411,  -205, -1571,
    1223,    652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,      -8,  -320,  -666, -1618, -1162,   126,  1469,
    -853,    -90,  -271,   830,   107, -1421,  -247,  -951,
    -398,    961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,     587,   177,  -235,  -291,  -460,  1574,  1653,
    -246,    778,  1159,  -147,  -777,  1483,  -602,  1119,
    -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,    1097,   603,   610,  1322, -1285, -1465,   384,
    -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
    -108,   -308,   996,   991,   958, -1460,  1522,  1628
];

fn fqmul(a: i16, b: i16) -> i16 {
    let d = (a as i32) * (b as i32);
    let t = (d as i16).wrapping_mul(QINV);
    ((d - (t as i32) * KYBER_Q32) >> 16) as i16
}

fn barrett_reduce(a: i16) -> i16 {
    let mut t = ((20159 * (a as i32) + (1 << 25)) >> 26) as i16;
    t = t.wrapping_mul(KYBER_Q);
    a.wrapping_sub(t)
}

fn mont_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV);
    ((a - (t as i32) * KYBER_Q32) >> 16) as i16
}

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
            if d1 < KYBER_Q {
                buf[j] = d1;
                j += 1;
            }
            if d2 < KYBER_Q && j < KYBER_N {
                buf[j] = d2;
                j += 1;
            }
        }
        Self(buf)
    }

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

    pub(crate) fn ntt(&mut self) {
        let mut k = 1;
        for len in [128, 64, 32, 16, 8, 4, 2] {
            for start in (0..256).step_by(2 * len) {
                let zeta = ZETAS[k];
                k += 1;
                for j in start..(start + len) {
                    let t = fqmul(zeta, self.0[j + len]);
                    self.0[j + len] = self.0[j] - t;
                    self.0[j] += t;
                }
            }
        }
    }

    pub(crate) fn inv_ntt(&mut self) {
        const F: i16 = 1441;
        let mut k = 127;
        for len in [2, 4, 8, 16, 32, 64, 128] {
            for start in (0..256).step_by(2 * len) {
                let zeta = ZETAS[k];
                k -= 1;
                for j in start..(start + len) {
                    let t = self.0[j];
                    self.0[j] = barrett_reduce(t + self.0[j + len]);
                    self.0[j + len] -= t;
                    self.0[j + len] = fqmul(zeta, self.0[j + len]);
                }
            }
        }
        for coef in self.0.iter_mut() {
            *coef = fqmul(*coef, F);
        }
    }

    pub(crate) fn radd(&mut self, rhs: &Self) {
        for (rc, &ac) in self.0.iter_mut().zip(rhs.0.iter()) {
            *rc += ac;
        }
    }

    pub(crate) fn lsub(&mut self, lhs: &Self) {
        for (rc, &ac) in self.0.iter_mut().zip(lhs.0.iter()) {
            *rc = ac - *rc;
        }
    }

    pub(crate) fn reduce(&mut self) {
        for coef in self.0.iter_mut() {
            *coef = barrett_reduce(*coef);
        }
    }

    pub(crate) fn mont(&mut self) {
        for coef in self.0.iter_mut() {
            *coef = mont_reduce((*coef as i32) * 1353); // 2^32 % q
        }
    }

    pub(crate) fn mul_mont(&self, rhs: &Self) -> Self {
        let mut r = Self::ZERO;
        macro_rules! basemul {
            ($i:expr, $zeta:expr) => {
                r.0[$i]      = fqmul(self.0[$i + 1], rhs.0[$i + 1]);
                r.0[$i]      = fqmul(r.0[$i],        $zeta);
                r.0[$i]     += fqmul(self.0[$i],     rhs.0[$i]);
                r.0[$i + 1]  = fqmul(self.0[$i],     rhs.0[$i + 1]);
                r.0[$i + 1] += fqmul(self.0[$i + 1], rhs.0[$i]);
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
            let t0 = (src[0] + ((src[0] >> 15) & KYBER_Q)) as u16;
            let t1 = (src[1] + ((src[1] >> 15) & KYBER_Q)) as u16;
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
                let u = coef + ((coef >> 15) & KYBER_Q);
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
            coefs[0] = ((((src & 0xf) as i32) * KYBER_Q32 + 8) >> 4) as i16;
            coefs[1] = ((((src >> 4) as i32) * KYBER_Q32 + 8) >> 4) as i16;
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
