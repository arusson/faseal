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

use std::ops::{
    Add, AddAssign,
    Index, IndexMut,
    Mul, MulAssign,
    Neg,
    Sub, SubAssign,
};

use subtle::ConstantTimeEq;

#[derive(Clone, Copy)]
pub(crate) struct Fe {
    pub(crate) buf: [u64; 5]
}

// Constants
impl Fe {
    pub(crate) const ZERO: Fe = Fe { buf: [0; 5] };
    pub(crate) const ONE: Fe = Fe { buf: [1, 0, 0, 0, 0] };

    // sqrt(-1)
    pub(crate) const SQRTM1: Fe = Fe {
        buf: [
            1718705420411056,
            234908883556509,
            2233514472574048,
            2117202627021982,
            765476049583133
        ]
    };

    // d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
    pub(crate) const ED25519_D: Fe = Fe {
        buf: [
            929955233495203,
            466365720129213,
            1662059464998953,
            2033849074728123,
            1442794654840575
        ]
    };

    // 2 * d = 16295367250680780974490674513165176452449235426866156013048779062215315747161
    pub(crate) const ED25519_D2: Fe = Fe {
        buf: [
            1859910466990425,
            932731440258426,
            1072319116312658,
            1815898335770999,
            633789495995903
        ]
    };
}

impl Index<usize> for Fe {
    type Output = u64;
    fn index(&self, index: usize) -> &Self::Output {
        &self.buf[index]
    }
}

impl IndexMut<usize> for Fe {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.buf[index]
    }
}

impl AddAssign<&Fe> for Fe {
    fn add_assign(&mut self, rhs: &Fe) {
        self[0] += rhs[0];
        self[1] += rhs[1];
        self[2] += rhs[2];
        self[3] += rhs[3];
        self[4] += rhs[4];
    }
}

impl Add<&Fe> for &Fe {
    type Output = Fe;
    fn add(self, rhs: &Fe) -> Self::Output {
        let mut out = *self;
        out += rhs;
        out
    }
}

impl SubAssign<&Fe> for Fe {
    fn sub_assign(&mut self, rhs: &Fe) {
        let mask = 0x7ffffffffffff_u64;
        let mut g = *rhs;
        g[1] += g[0] >> 51;
        g[0] &= mask;
        g[2] += g[1] >> 51;
        g[1] &= mask;
        g[3] += g[2] >> 51;
        g[2] &= mask;
        g[4] += g[3] >> 51;
        g[3] &= mask;
        g[0] += 19 * (g[4] >> 51);
        g[4] &= mask;

        self[0] = (self[0] + 0xfffffffffffda_u64) - g[0];
        self[1] = (self[1] + 0xffffffffffffe_u64) - g[1];
        self[2] = (self[2] + 0xffffffffffffe_u64) - g[2];
        self[3] = (self[3] + 0xffffffffffffe_u64) - g[3];
        self[4] = (self[4] + 0xffffffffffffe_u64) - g[4];
    }
}

impl Sub<&Fe> for &Fe {
    type Output = Fe;
    fn sub(self, rhs: &Fe) -> Self::Output {
        let mut out = *self;
        out -= rhs;
        out
    }
}

impl Neg for &Fe {
    type Output = Fe;
    fn neg(self) -> Self::Output {
        &Fe::ZERO - self
    }
}

impl MulAssign<&Fe> for Fe {
    fn mul_assign(&mut self, rhs: &Fe) {
        let mask = 0x0007_ffff_ffff_ffff_u64;

        let f0 = rhs[0] as u128;
        let f1 = rhs[1] as u128;
        let f2 = rhs[2] as u128;
        let f3 = rhs[3] as u128;
        let f4 = rhs[4] as u128;

        let g0 = self[0] as u128;
        let g1 = self[1] as u128;
        let g2 = self[2] as u128;
        let g3 = self[3] as u128;
        let g4 = self[4] as u128;

        let f1_19 = 19 * f1;
        let f2_19 = 19 * f2;
        let f3_19 = 19 * f3;
        let f4_19 = 19 * f4;

        let     r0 = f0 * g0 + f1_19 * g4 + f2_19 * g3 + f3_19 * g2 + f4_19 * g1;
        let mut r1 = f0 * g1 +    f1 * g0 + f2_19 * g4 + f3_19 * g3 + f4_19 * g2;
        let mut r2 = f0 * g2 +    f1 * g1 +    f2 * g0 + f3_19 * g4 + f4_19 * g3;
        let mut r3 = f0 * g3 +    f1 * g2 +    f2 * g1 +    f3 * g0 + f4_19 * g4;
        let mut r4 = f0 * g4 +    f1 * g3 +    f2 * g2 +    f3 * g1 +    f4 * g0;

        let mut r00   = r0 as u64 & mask;
        let mut carry = (r0 >> 51) as u64;
        r1           += carry as u128;
        let mut r01   = r1 as u64 & mask;
        carry         = (r1 >> 51) as u64;
        r2           += carry as u128;
        let mut r02   = r2 as u64 & mask;
        carry         = (r2 >> 51) as u64;
        r3           += carry as u128;
        let r03       = r3 as u64 & mask;
        carry         = (r3 >> 51) as u64;
        r4           += carry as u128;
        let r04       = r4 as u64 & mask;
        carry         = (r4 >> 51) as u64;
        r00          += 19 * carry;
        carry         = r00 >> 51;
        r00          &= mask;
        r01          += carry;
        carry         = r01 >> 51;
        r01          &= mask;
        r02          += carry;

        self[0] = r00;
        self[1] = r01;
        self[2] = r02;
        self[3] = r03;
        self[4] = r04;
    }
}

impl Mul<&Fe> for &Fe {
    type Output = Fe;
    fn mul(self, rhs: &Fe) -> Self::Output {
        let mut output = *self;
        output *= rhs;
        output
    }
}

impl Mul<u32> for &Fe {
    type Output = Fe;
    fn mul(self, rhs: u32) -> Self::Output {
        let mask = 0x0007_ffff_ffff_ffff_u64;
        let sn = rhs as u128;
        let mut a = self[0] as u128 * sn;

        let mut output = Fe::ZERO;
        output[0] = a as u64 & mask;
        a  = self[1] as u128 * sn + (a >> 51);
        output[1] = a as u64 & mask;
        a  = self[2] as u128 * sn + (a >> 51);
        output[2] = a as u64 & mask;
        a  = self[3] as u128 * sn + (a >> 51);
        output[3] = a as u64 & mask;
        a  = self[4] as u128 * sn + (a >> 51);
        output[4] = a as u64 & mask;
        output[0] += ((a >> 51) * 19) as u64;
        output
    }
}

impl Fe {
    pub(crate) fn cmov(&mut self, other: &Fe, cond: u64) {
        let mask = (-(cond as i64)) as u64;

        let x0 = (self[0] ^ other[0]) & mask;
        let x1 = (self[1] ^ other[1]) & mask;
        let x2 = (self[2] ^ other[2]) & mask;
        let x3 = (self[3] ^ other[3]) & mask;
        let x4 = (self[4] ^ other[4]) & mask;

        self[0] ^= x0;
        self[1] ^= x1;
        self[2] ^= x2;
        self[3] ^= x3;
        self[4] ^= x4;
    }

    pub(crate) fn cswap(&mut self, other: &mut Fe, cond: u64) {   
        let mask = (-(cond as i64)) as u64;

        let x0 = (self[0] ^ other[0]) & mask;
        let x1 = (self[1] ^ other[1]) & mask;
        let x2 = (self[2] ^ other[2]) & mask;
        let x3 = (self[3] ^ other[3]) & mask;
        let x4 = (self[4] ^ other[4]) & mask;

        self[0] ^= x0;
        self[1] ^= x1;
        self[2] ^= x2;
        self[3] ^= x3;
        self[4] ^= x4;

        other[0] ^= x0;
        other[1] ^= x1;
        other[2] ^= x2;
        other[3] ^= x3;
        other[4] ^= x4;
    }

    fn reduce(&self) -> Fe {
        let mask = 0x0007_ffff_ffff_ffff_u128;
        let mut t = [0u128; 5];

        t[0] = self[0] as u128;
        t[1] = self[1] as u128;
        t[2] = self[2] as u128;
        t[3] = self[3] as u128;
        t[4] = self[4] as u128;

        t[1] += t[0] >> 51;
        t[0] &= mask;
        t[2] += t[1] >> 51;
        t[1] &= mask;
        t[3] += t[2] >> 51;
        t[2] &= mask;
        t[4] += t[3] >> 51;
        t[3] &= mask;
        t[0] += 19 * (t[4] >> 51);
        t[4] &= mask;

        t[1] += t[0] >> 51;
        t[0] &= mask;
        t[2] += t[1] >> 51;
        t[1] &= mask;
        t[3] += t[2] >> 51;
        t[2] &= mask;
        t[4] += t[3] >> 51;
        t[3] &= mask;
        t[0] += 19 * (t[4] >> 51);
        t[4] &= mask;

        // now t is between 0 and 2^255-1, properly carried.
        // case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1.

        t[0] += 19;

        t[1] += t[0] >> 51;
        t[0] &= mask;
        t[2] += t[1] >> 51;
        t[1] &= mask;
        t[3] += t[2] >> 51;
        t[2] &= mask;
        t[4] += t[3] >> 51;
        t[3] &= mask;
        t[0] += 19 * (t[4] >> 51);
        t[4] &= mask;

        // now between 19 and 2^255-1 in both cases, and offset by 19.

        t[0] += 0x8000000000000 - 19;
        t[1] += 0x8000000000000 - 1;
        t[2] += 0x8000000000000 - 1;
        t[3] += 0x8000000000000 - 1;
        t[4] += 0x8000000000000 - 1;

        // now between 2^255 and 2^256-20, and offset by 2^255.

        t[1] += t[0] >> 51;
        t[0] &= mask;
        t[2] += t[1] >> 51;
        t[1] &= mask;
        t[3] += t[2] >> 51;
        t[2] &= mask;
        t[4] += t[3] >> 51;
        t[3] &= mask;
        t[4] &= mask;

        Fe { buf: [ t[0] as u64, t[1] as u64, t[2] as u64, t[3] as u64, t[4] as u64] }
    }

    pub(crate) fn bytes(&self) -> [u8; 32] {
        let t = self.reduce();
        let mut output = [0u8; 32];
        output[..8].copy_from_slice(&u64::to_le_bytes(t[0] | (t[1] << 51)));
        output[8..16].copy_from_slice(&u64::to_le_bytes((t[1] >> 13) | (t[2] << 38)));
        output[16..24].copy_from_slice(&u64::to_le_bytes((t[2] >> 26) | (t[3] << 25)));
        output[24..32].copy_from_slice(&u64::to_le_bytes((t[3] >> 39) | (t[4] << 12)));
        output
    }

    pub(crate) fn is_negative(&self) -> bool {
        let s = self.bytes();
        (s[0] & 1) == 1
    }

    pub(crate) fn is_zero(&self) -> bool {
        let zero = [0u8; 32];
        let buf = self.bytes();
        buf.ct_eq(&zero).into()
    }

    pub(crate) fn sqr(&self) -> Fe {
        let mask = 0x0007_ffff_ffff_ffff_u64;

        let f0 = self[0] as u128;
        let f1 = self[1] as u128;
        let f2 = self[2] as u128;
        let f3 = self[3] as u128;
        let f4 = self[4] as u128;

        let f0_2 = f0 << 1;
        let f1_2 = f1 << 1;

        let f1_38 = 38 * f1;
        let f2_38 = 38 * f2;
        let f3_38 = 38 * f3;

        let f3_19 = 19 * f3;
        let f4_19 = 19 * f4;

        let r0     =   f0 * f0 + f1_38 * f4 + f2_38 * f3;
        let mut r1 = f0_2 * f1 + f2_38 * f4 + f3_19 * f3;
        let mut r2 = f0_2 * f2 +    f1 * f1 + f3_38 * f4;
        let mut r3 = f0_2 * f3 +  f1_2 * f2 + f4_19 * f4;
        let mut r4 = f0_2 * f4 +  f1_2 * f3 +    f2 * f2;

        let mut r00    = r0 as u64 & mask;
        let mut carry  = (r0 >> 51) as u64;
        r1            += carry as u128;
        let mut r01    = r1 as u64 & mask;
        carry          = (r1 >> 51) as u64;
        r2            += carry as u128;
        let mut r02    = r2 as u64 & mask;
        carry          = (r2 >> 51) as u64;
        r3            += carry as u128;
        let r03        = r3 as u64 & mask;
        carry          = (r3 >> 51) as u64;
        r4            += carry as u128;
        let r04        = r4 as u64 & mask;
        carry          = (r4 >> 51) as u64;
        r00           += 19 * carry;
        carry          = r00 >> 51;
        r00           &= mask;
        r01           += carry;
        carry         = r01 >> 51;
        r01           &= mask;
        r02           += carry;

        Fe { buf: [r00, r01, r02, r03, r04] }
    }

    pub(crate) fn from_bytes(input: &[u8; 32]) -> Fe {
        let mask = 0x0007_ffff_ffff_ffff_u64;

        let mut output = Fe::ZERO;
        output[0] = u64::from_le_bytes(input[..8].try_into().unwrap()) & mask;
        output[1] = (u64::from_le_bytes(input[6..14].try_into().unwrap()) >> 3) & mask;
        output[2] = (u64::from_le_bytes(input[12..20].try_into().unwrap()) >> 6) & mask;
        output[3] = (u64::from_le_bytes(input[19..27].try_into().unwrap()) >> 1) & mask;
        output[4] = (u64::from_le_bytes(input[24..].try_into().unwrap()) >> 12) & mask;
        output
    }

    pub(crate) fn invert(&self) -> Fe {
        let mut t0 = self.sqr();
        let mut t1 = t0.sqr();
        t1 = t1.sqr();
        t1 = &t1 * self;
        t0 = &t0 * &t1;
        let mut t2 = t0.sqr();
        t1 = &t1 * &t2;
        t2 = t1.sqr();

        for _ in 0..4 {
            t2 = t2.sqr();
        }
        t1 = &t1 * &t2;
        t2 = t1.sqr();
        for _ in 0..9 {
            t2 = t2.sqr();
        }
        t2 = &t2 * &t1;
        let mut t3 = t2.sqr();
        for _ in 0..19 {
            t3 = t3.sqr();
        }
        t2 = &t2 * &t3;
        for _ in 0..10 {
            t2 = t2.sqr();
        }
        t1 = &t1 * &t2;
        t2 = t1.sqr();
        for _ in 0..49 {
            t2 = t2.sqr();
        }
        t2 = &t2 * &t1;
        t3 = t2.sqr();
        for _ in 0..99 {
            t3 = t3.sqr();
        }
        t2 = &t2 * &t3;
        for _ in 0..50 {
            t2 = t2.sqr();
        }
        t1 = &t1 * &t2;
        for _ in 0..5 {
            t1 = t1.sqr();
        }
        &t1 * &t0
    }

    // returns z^((p-5)/8) = z^(2^252-3)
    // used to compute square roots since we have p=5 (mod 8); see Cohen and Frey.
    pub(crate) fn pow22523(&self) -> Fe {    
        let mut t0 = self.sqr();
        let mut t1 = t0.sqr();
        t1 = t1.sqr();
        t1 = &t1 * self;
        t0 = &t0 * &t1;
        t0 = t0.sqr();
        t0 = &t0 * &t1;
        t1 = t0.sqr();
        for _ in 0..4 {
            t1 = t1.sqr();
        }
        t0 = &t0 * &t1;
        t1 = t0.sqr();
        for _ in 0..9 {
            t1 = t1.sqr();
        }
        t1 = &t1 * &t0;
        let mut t2 = t1.sqr();
        for _ in 0..19 {
            t2 = t2.sqr();
        }
        t1 = &t1 * &t2;
        for _ in 0..10 {
            t1 = t1.sqr();
        }
        t0 = &t0 * &t1;
        t1 = t0.sqr();
        for _ in 0..49 {
            t1 = t1.sqr();
        }
        t1 = &t1 * &t0;
        t2 = t1.sqr();
        for _ in 0..99 {
            t2 = t2.sqr();
        }
        t1 = &t1 * &t2;
        for _ in 0..50 {
            t1 = t1.sqr();
        }
        t0 = &t0 * &t1;
        t0 = t0.sqr();
        t0 = t0.sqr();
        self * &t0
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use super::Fe;
    use hex_literal::hex;

    #[test]
    fn test_field25519_mul() {
        let a = hex!("b1dc286313d7299a176f9374958367d4a3d56d9608c0cad7678523c802eda07f");
        let expected = hex!("ce6a443014d9739f7fc518b426243183a09c4edb1a4686297c57a8e4da052c11");

        // Square-and-multiply to compute base^exponent
        let base = Fe::from_bytes(&a);
        let mut acc = Fe::ONE;
        let exponent = hex!("2f837addb1f94760139aaecb986f16159a3ce78e1c2fb7f4dc56b98caf92be79");

        for b in exponent {
            for i in (0..8).rev() {
                let bit = (b >> i) & 1;
                acc = acc.sqr();
                if bit == 1 {
                    acc *= &base;
                }
            }
        }
        let res = acc.bytes();
        assert_eq!(res, expected);
    }

    #[test]
    fn test_field25519_invert() {
        let mut buf = [0u8; 32];
        rand::rng().fill_bytes(&mut buf);
        let a = Fe::from_bytes(&buf);
        let b = a.invert();
        let c = &a * &b;
        let d = c.bytes();
        let mut e = [0u8; 32];
        e[0] = 1;
        assert_eq!(d, e);
    }

    #[test]
    fn test_add() {
        let mut buf = [0u8; 32];
        rand::rng().fill_bytes(&mut buf);
        let mut a = Fe::from_bytes(&buf);
        rand::rng().fill_bytes(&mut buf);
        let b = Fe::from_bytes(&buf);

        let c = &a + &b; // a + b
        let d = &c - &b; // a

        let a_bytes = a.bytes();
        let d_bytes = d.bytes();

        assert_eq!(a_bytes, d_bytes);

        a += &b; // a + b

        let apb_bytes = a.bytes();
        let c_bytes = c.bytes();
        assert_eq!(apb_bytes, c_bytes);

        a -= &b; // a

        let a_bytes2 = a.bytes();
        assert_eq!(a_bytes, a_bytes2);
    }

    #[test]
    fn test_mul_32() {
        let k = hex!("dd402e186ae0662c66048a2957b882062fbdcdc682c8a7cbf1e38ea624d0635d");
        let kmul_expected = hex!(
            "3a84600e38b6ea54bab6becb8b40bd39340711ff96584cd23669c8117eaaef46"
        );

        let k = Fe::from_bytes(&k);
        let kmul = &k * 121666;
        assert_eq!(kmul.bytes(), kmul_expected);
    }
}
