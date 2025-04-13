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
    ml_dsa::{
        ML_DSA_N,
        ML_DSA_Q,
        QINV,
        GAMMA_1,
        GAMMA_2,
        ETA,
        LAMBDA4,
        TAU
    }
};

const ZETAS: [i32; ML_DSA_N] = [
    0,           25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
    1826347,   2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
    2725464,   1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
    2706023,     95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
    -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
    -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,     531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
    -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
    3412210,   -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
    -671102,  -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
    -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
    -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548,   -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
    1285669,  -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
    2091667,   3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,    2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,    1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
    -655327,  -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,     286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
    2842341,   2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
    -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
    -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
    -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
    -542412,  -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
    -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
    -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
    -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
    -426683,   1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
    -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
    -554416,   3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
];

fn mont_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    ((a - (t as i64) * (ML_DSA_Q as i64)) >> 32) as i32
}

fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * ML_DSA_Q
}

#[derive(Clone)]
pub(crate) struct Poly(pub(crate) [i32; ML_DSA_N]);

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Poly {
    pub(crate) const ETA_LEN:   usize = 32 * 4;
    pub(crate) const GAMMA_LEN: usize = 32 * 20;
    pub(crate) const T0_LEN:    usize = 32 * 13;
    pub(crate) const T1_LEN:    usize = 32 * 10;
    pub(crate) const W1_LEN:    usize = 32 * 4;
    pub(crate) const ZERO: Self = Self([0; ML_DSA_N]);
 
    pub(crate) fn sample_ntt(input: &[u8; 32], s: u8, r: u8) -> Self {
        let mut xof = Shake128::init();
        xof.absorb(&[input, &[s, r]]);
        let mut buf = [0i32; ML_DSA_N];
        let mut j = 0;
        while j < ML_DSA_N {
            let mut c = [0u8; 3];
            xof.squeeze(&mut c);
            c[2] &= 0x7f;
            let z = ((c[2] as i32) << 16) | ((c[1] as i32) << 8) | (c[0] as i32);
            if z <= ML_DSA_Q {
                buf[j] = z;
                j += 1;
            }
        }
        Self(buf)
    }

    pub(crate) fn sample_bounded(input: &[u8; 64], r: [u8; 2]) -> Self {
        let mut xof = Shake256::init();
        xof.absorb(&[input, &r]);
        let mut buf = [0i32; ML_DSA_N];
        let mut j = 0;
        while j < ML_DSA_N {
            let mut z = [0u8; 1];
            xof.squeeze(&mut z);
            let z0 = (z[0] & 0xf) as i32;
            let z1 = (z[0] >> 4) as i32;
            if z0 < 9 {
                buf[j] = 4 - z0;
                j += 1;
            }
            if z1 < 9 && j < ML_DSA_N {
                buf[j] = 4 - z1;
                j += 1;
            }
        }
        xof.zeroize();
        Self(buf)
    }

    pub(crate) fn sample_gamma(input: &[u8; 64], r: [u8; 2]) -> Self {
        let mut v = [0u8; Self::GAMMA_LEN];
        Shake256::hash_into(&[input, &r], &mut v);
        Self::unpack_bytes_gamma(&v)
    }

    pub(crate) fn sample_in_ball(input: &[u8; LAMBDA4]) -> Self {
        let mut poly = Self::ZERO;
        let mut xof = Shake256::init();
        xof.absorb(&[input]);
    
        let mut s = [0u8; 8];
        xof.squeeze(&mut s);
        let mut signs = u64::from_le_bytes(s);
    
        for i in (256 - TAU)..256 {
            let j = loop {
                let mut j = [0u8; 1];
                xof.squeeze(&mut j);
                if j[0] as usize <= i {
                    break j[0] as usize;
                }
            };
            poly.0[i] = poly.0[j];
            poly.0[j] = 1 - 2 * ((signs & 1) as i32);
            signs >>= 1;
        }
        xof.zeroize();

        poly
    }

    pub(crate) fn ntt(&mut self) {
        let mut k = 1;
        for len in [128, 64, 32, 16, 8, 4, 2, 1] {
            for start in (0..ML_DSA_N).step_by(2*len) {
                let zeta = ZETAS[k];
                k += 1;
                for j in start..(start + len) {
                    let t = mont_reduce((zeta as i64) * (self.0[j + len] as i64));
                    self.0[j + len] = self.0[j] - t;
                    self.0[j] += t;
                }
            }
        }
    }

    pub(crate) fn inv_ntt(&mut self) {
        const F: i64 = 41_978;
        let mut k = 255;
        for len in [1, 2, 4, 8, 16, 32, 64, 128] {
            for start in (0..256).step_by(2*len) {
                let zeta = -ZETAS[k];
                k -= 1;
                for j in start..(start + len) {
                    let t = self.0[j];
                    self.0[j] = t + self.0[j + len];
                    self.0[j + len] = t - self.0[j + len];
                    self.0[j + len] = mont_reduce((zeta as i64) * (self.0[j + len] as i64));
                }
            }
        }

        for coef in self.0.iter_mut() {
            *coef = mont_reduce(F * (*coef as i64));
        }
    }

    pub(crate) fn mul_mont(&self, rhs: &Self) -> Self {
        let mut r = Self::ZERO;
        for (rc, (&ac, &bc)) in r.0.iter_mut().zip(self.0.iter().zip(rhs.0.iter())) {
            *rc = mont_reduce((ac as i64) * (bc as i64));
        }
        r
    }

    pub(crate) fn radd(&mut self, rhs: &Self) {
        for (ac, &bc) in self.0.iter_mut().zip(rhs.0.iter()) {
            *ac += bc;
        }
    }

    pub(crate) fn rsub(&mut self, rhs: &Self) {
        for (ac, &bc) in self.0.iter_mut().zip(rhs.0.iter()) {
            *ac -= bc;
        }
    }

    pub(crate) fn reduce(&mut self) {
        for coef in self.0.iter_mut() {
            *coef = reduce32(*coef);
        }
    }

    pub(crate) fn power2round(&mut self) -> Self {
        let mut t0 = Self::ZERO;
        for (t1c, t0c) in self.0.iter_mut().zip(t0.0.iter_mut()) {
            *t1c += (*t1c >> 31) & ML_DSA_Q; // make the coefficient in [0, q - 1] first
            let t = (*t1c + (1 << 12) - 1) >> 13;
            *t0c = *t1c - (t << 13);
            *t1c = t;
        }
        t0
    }

    pub(crate) fn decompose(&mut self, a: &mut Self) {
        for (coef, acoef) in self.0.iter_mut().zip(a.0.iter_mut()) {
            *coef += (*coef >> 31) & ML_DSA_Q; // make the coefficient in [0, q - 1] first
            let mut a1 = (*coef + 127) >> 7;
            a1 = (a1 * 1025 + (1 << 21)) >> 22;
            a1 &= 0xf;

            *acoef = *coef - a1 * 2 * GAMMA_2;
            *acoef -= (((ML_DSA_Q - 1)/2 - *acoef) >> 31) & ML_DSA_Q;
            *coef = a1;
        }
    }

    pub(crate) fn pack_bytes_t1(&self, buffer: &mut [u8; Self::T1_LEN]) {
        for (src, dst) in self.0.chunks_exact(4).zip(buffer.chunks_exact_mut(5)) {
            dst[0] =   src[0]                        as u8;
            dst[1] = ((src[0] >> 8) | (src[1] << 2)) as u8;
            dst[2] = ((src[1] >> 6) | (src[2] << 4)) as u8;
            dst[3] = ((src[2] >> 4) | (src[3] << 6)) as u8;
            dst[4] =  (src[3] >> 2)                  as u8;
        }
    }

    pub(crate) fn unpack_bytes_t1(buffer: &[u8; Self::T1_LEN]) -> Self {
        let mut poly = Poly::ZERO;
        for (src, dst) in buffer.chunks_exact(5).zip(poly.0.chunks_exact_mut(4)) {
            dst[0]  = (src[0] as i32) | ((src[1] as i32) << 8);
            dst[0] &= 0x3ff;

            dst[1]  = ((src[1] as i32) >> 2) | ((src[2] as i32) << 6);
            dst[1] &= 0x3ff;

            dst[2]  = ((src[2] as i32) >> 4) | ((src[3] as i32) << 4);
            dst[2] &= 0x3ff;

            dst[3]  = ((src[3] as i32) >> 6) | ((src[4] as i32) << 2);
        }
        poly
    }

    pub(crate) fn pack_bytes_t0(&self, buffer: &mut [u8; Self::T0_LEN]) {
        for (src, dst) in self.0.chunks_exact(8).zip(buffer.chunks_exact_mut(13)) {
            let mut t = [0u32; 8];
            t[0] = ((1 << 12) - src[0]) as u32;
            t[1] = ((1 << 12) - src[1]) as u32;
            t[2] = ((1 << 12) - src[2]) as u32;
            t[3] = ((1 << 12) - src[3]) as u32;
            t[4] = ((1 << 12) - src[4]) as u32;
            t[5] = ((1 << 12) - src[5]) as u32;
            t[6] = ((1 << 12) - src[6]) as u32;
            t[7] = ((1 << 12) - src[7]) as u32;

            dst[0]  =   t[0]                       as u8;
            dst[1]  = ((t[0] >> 8)  | (t[1] << 5)) as u8;
            dst[2]  =  (t[1] >> 3)                 as u8;
            dst[3]  = ((t[1] >> 11) | (t[2] << 2)) as u8;
            dst[4]  = ((t[2] >> 6)  | (t[3] << 7)) as u8;
            dst[5]  =  (t[3] >> 1)                 as u8;
            dst[6]  = ((t[3] >> 9)  | (t[4] << 4)) as u8;
            dst[7]  =  (t[4] >> 4)                 as u8;
            dst[8]  = ((t[4] >> 12) | (t[5] << 1)) as u8;
            dst[9]  = ((t[5] >> 7)  | (t[6] << 6)) as u8;
            dst[10] =  (t[6] >> 2)                 as u8;
            dst[11] = ((t[6] >> 10) | (t[7] << 3)) as u8;
            dst[12] =  (t[7] >> 5)                 as u8;
        }
    }

    pub(crate) fn unpack_bytes_t0(buffer: &[u8; Self::T0_LEN]) -> Self {
        let mut poly = Self::ZERO;
        for (src, dst) in buffer.chunks_exact(13).zip(poly.0.chunks_exact_mut(8)) {
            dst[0] = (src[0] as i32) | ((src[1] as i32) << 8);
            dst[0] = (1 << 12) - (dst[0] & 0x1fff);

            dst[1] = ((src[1] as i32) >> 5) | ((src[2] as i32) << 3) | ((src[3] as i32) << 11);
            dst[1] = (1 << 12) - (dst[1] & 0x1fff);

            dst[2] = ((src[3] as i32) >> 2) | ((src[4] as i32) << 6);
            dst[2] = (1 << 12) - (dst[2] & 0x1fff);

            dst[3] = ((src[4] as i32) >> 7) | ((src[5] as i32) << 1) | ((src[6] as i32) << 9);
            dst[3] = (1 << 12) - (dst[3] & 0x1fff);

            dst[4] = ((src[6] as i32) >> 4) | ((src[7] as i32) << 4) | ((src[8] as i32) << 12);
            dst[4] = (1 << 12) - (dst[4] & 0x1fff);

            dst[5] = ((src[8] as i32) >> 1) | ((src[9] as i32) << 7);
            dst[5] = (1 << 12) - (dst[5] & 0x1fff);

            dst[6] = ((src[9] as i32) >> 6) | ((src[10] as i32) << 2) | ((src[11] as i32) << 10);
            dst[6] = (1 << 12) - (dst[6] & 0x1fff);

            dst[7] = ((src[11] as i32) >> 3) | ((src[12] as i32) << 5);
            dst[7] = (1 << 12) - (dst[7] & 0x1fff);
        }
        poly
    }

    pub(crate) fn pack_bytes_eta(&self, buffer: &mut [u8; Self::ETA_LEN]) {
        for (src, dst) in self.0.chunks_exact(2).zip(buffer.iter_mut()) {
            let mut t = [0u8; 2];
            t[0] = (ETA - src[0]) as u8;
            t[1] = (ETA - src[1]) as u8;

            *dst = t[0] | (t[1] << 4);
        }
    }

    pub(crate) fn unpack_bytes_eta(buffer: &[u8; Self::ETA_LEN]) -> Self {
        let mut poly = Self::ZERO;
        for (src, dst) in buffer.iter().zip(poly.0.chunks_exact_mut(2)) {
            dst[0] = ETA -  (src       & 0xf) as i32;
            dst[1] = ETA - ((src >> 4) & 0xf) as i32;
        }
        poly
    }

    pub(crate) fn pack_bytes_gamma(&self, buffer: &mut [u8; Self::GAMMA_LEN]) {
        for (src, dst) in self.0.chunks_exact(2).zip(buffer.chunks_exact_mut(5)) {
            let mut t = [0u32; 2];
            t[0] = (GAMMA_1 - src[0]) as u32;
            t[1] = (GAMMA_1 - src[1]) as u32;
            dst[0] =   t[0]        as u8;
            dst[1] =  (t[0] >> 8)  as u8;
            dst[2] = ((t[0] >> 16) as u8) | ((t[1] << 4) as u8);
            dst[3] =  (t[1] >> 4)  as u8;
            dst[4] =  (t[1] >> 12) as u8;
        }
    }

    pub(crate) fn unpack_bytes_gamma(buffer: &[u8; Self::GAMMA_LEN]) -> Self {
        let mut poly = Self::ZERO;
        for (src, dst) in buffer.chunks_exact(5).zip(poly.0.chunks_exact_mut(2)) {
            dst[0] = (src[0] as i32) | ((src[1] as i32) << 8) | ((src[2] as i32) << 16);
            dst[0] = GAMMA_1 - (dst[0] & 0xfffff);

            dst[1] = ((src[2] as i32) >> 4) | ((src[3] as i32) << 4) | ((src[4] as i32) << 12);
            dst[1] = GAMMA_1 - dst[1];
        }
        poly
    }

    pub(crate) fn pack_bytes_w1(&self, buffer: &mut [u8; Self::W1_LEN]) {
        for (src, dst) in self.0.chunks_exact(2).zip(buffer.iter_mut()) {
            *dst = (src[0] | (src[1]  << 4)) as u8;
        }
    }

    pub(crate) fn check_norm(&self, norm: i32) -> bool {
        for coef in self.0 {
            let mut t = coef >> 31;
            t = coef - (t & (2 * coef));
            if t >= norm {
                return false;
            }
        }
        true
    }

    pub(crate) fn make_hint(&mut self, a: &Self, b: &Self) -> usize {
        let mut s = 0;
        for (hc, (&ac, &bc)) in self.0.iter_mut().zip(a.0.iter().zip(b.0.iter())) {
            *hc = if !(-GAMMA_2..=GAMMA_2).contains(&ac) || ac == -GAMMA_2 && bc != 0 {
                1
            }
            else {
                0
            };
            s += *hc as usize;
        }
        s
    }

    pub(crate) fn use_hint(&mut self, hint: &Self) {
        for (c, &hc) in self.0.iter_mut().zip(hint.0.iter()) {
            *c += (*c >> 31) & ML_DSA_Q; // make the coefficient in [0, q - 1] first
            let mut a1 = (*c + 127) >> 7;
            a1 = (a1 * 1025 + (1 << 21)) >> 22;
            a1 &= 0xf;
        
            let mut a0 = *c - a1 * 2 * GAMMA_2;
            a0 -= (((ML_DSA_Q - 1)/2 - a0) >> 31) & ML_DSA_Q;
            *c = if hc == 0 {
                a1
            }
            else if a0 > 0 {
                (a1 + 1) & 15
            }
            else {
                (a1 - 1) & 15
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use super::Poly;

    #[test]
    fn test_pack_bytes_gamma() {
        let mut buf1 = [0u8; 640];
        rand::rng().fill_bytes(&mut buf1);
        let poly = Poly::unpack_bytes_gamma(&buf1);
        let mut buf2 = [0u8; 640];
        poly.pack_bytes_gamma(&mut buf2);
        assert_eq!(buf1, buf2);
    }
}
