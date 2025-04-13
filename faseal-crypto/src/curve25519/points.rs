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
    Add, AddAssign, SubAssign
};
use crate::curve25519::field::Fe;

#[derive(Debug)]
pub(crate) struct PointError;

impl std::fmt::Display for PointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Curve25519: invalid point.")
    }
}

#[derive(Clone)]
pub(crate) struct Point {
    pub(crate) x: Fe,
    pub(crate) y: Fe,
    pub(crate) z: Fe,
    pub(crate) t: Fe
}

impl Point {
    pub(crate) const ZERO: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO
    };

    pub(crate) fn bytes(&self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = &self.x * &recip;
        let y = &self.y * &recip;
        let mut s = y.bytes();
    
        s[31] |= (x.is_negative() as u8) << 7;
        s
    }
    
    pub(crate) fn from_bytes_negate_vartime(s: &[u8; 32]) -> Result<Point, PointError> {
        if !point_is_canonical(s) {
            return Err(PointError);
        }

        let mut output = Point::ZERO;
        output.y = Fe::from_bytes(s);
        output.z = Fe::ONE;
        let mut u = output.y.sqr();
        let mut v = &u * &Fe::ED25519_D;
        u -= &output.z; // u = y^2-1
        v += &output.z; // v = dy^2+1

        let mut v3 = v.sqr();
        v3 *= &v; // v3 = v^3
        output.x = v3.sqr();
        output.x *= &v;
        output.x *= &u; // x = uv^7

        output.x = output.x.pow22523(); // x = (uv^7)^((q-5)/8)
        output.x *= &v3;
        output.x *= &u; // x = uv^3(uv^7)^((q-5)/8)

        let mut vxx = output.x.sqr();
        vxx *= &v;
        let m_root_check = &vxx - &u; // vx^2-u
        if !m_root_check.is_zero() {
            let p_root_check = &vxx + &u; // vx^2+u
            if !p_root_check.is_zero() {
                return Err(PointError);
            }
            output.x *= &Fe::SQRTM1;
        }

        if output.x.is_negative() as u8 == s[31] >> 7 {
            output.x = -&output.x;
        }
        output.t = &output.x * &output.y;

        Ok(output)
    }

    pub(crate) fn has_small_order(&self) -> bool {
        let recip = self.z.invert();
        let x = &self.x * &recip;
        let mut ret = x.is_zero() as usize;
        let y = &self.y * &recip;
        ret |= y.is_zero() as usize;
        let x_neg = -&self.x;
        let y_sqrtm1 = &y * &Fe::SQRTM1;
        let mut c = &y_sqrtm1 - &x;
        ret |= c.is_zero() as usize;
        c = &y_sqrtm1 - &x_neg;
        ret |= c.is_zero() as usize;
        ret != 0
    }

    pub(crate) fn dbl(&self) -> Point {
        // A = X1^2
        let mut t0 = self.x.sqr();
    
        // B = Y1^2
        let mut t1 = self.y.sqr();
    
        // C = 2*Z1^2
        let mut t2 = self.z.sqr();
        t2 = &t2 + &t2;

        // H = A+B
        let t3 = &t0 + &t1;
    
        // E = H-(X1+Y1)^2
        let mut t4 = &self.x + &self.y;
        t4 = t4.sqr();
        t4 = &t3 - &t4;

        // G = A-B
        t0 -= &t1;

        // F = C+G
        t1 = &t2 + &t0;

        // X3 = E*F, Y3 = G*H, T3 = E*H, Z3 = F*G
        let mut point = Point::ZERO;
        point.x = &t4 * &t1;
        point.y = &t0 * &t3;
        point.t = &t4 * &t3;
        point.z = &t1 * &t0;
        point
    }

    fn cmov(&mut self, u: &Point, cond: u64) {
        self.x.cmov(&u.x, cond);
        self.y.cmov(&u.y, cond);
        self.z.cmov(&u.z, cond);
        self.t.cmov(&u.t, cond);
    }

    fn cmov8(&mut self, precomp: &[Point; 8], b: i8) {
        let mut minust = Point::ZERO;
        let bnegative = negative(b);
        let babs =  b - (bnegative.wrapping_neg() as i8 & b) * (1i8 << 1);
        *self = Point::ZERO;
    
        self.cmov(&precomp[0], equal(babs, 1));
        self.cmov(&precomp[1], equal(babs, 2));
        self.cmov(&precomp[2], equal(babs, 3));
        self.cmov(&precomp[3], equal(babs, 4));
        self.cmov(&precomp[4], equal(babs, 5));
        self.cmov(&precomp[5], equal(babs, 6));
        self.cmov(&precomp[6], equal(babs, 7));
        self.cmov(&precomp[7], equal(babs, 8));
        minust.x = -&self.x;
        minust.y = self.y;
        minust.z = self.z;
        minust.t = -&self.t;
        self.cmov(&minust, bnegative as u64);
    }

    pub(crate) fn cmov8_base(&mut self, b: i8) {
        self.cmov8(&Point::BASE_PRECOMP, b);
    }
}

impl AddAssign<&Point> for Point {
    fn add_assign(&mut self, rhs: &Point) {
        // A = (Y1-X1)*(Y2-X2)
        let mut t0 = &self.y - &self.x;
        let mut t1 = &rhs.y - &rhs.x;
        t0 *= &t1;
    
        // B = (Y1+X1)*(Y2+X2)
        t1 = &self.y + &self.x;
        let mut t2 = &rhs.y + &rhs.x;
        t1 *= &t2;

        // C = T1*2*d*T2
        t2 = &Fe::ED25519_D2 * &rhs.t;
        t2 *= &self.t;

        // D = Z1*2*Z2
        let mut t3 = &rhs.z + &rhs.z;
        t3 *= &self.z;

        // E = B-A
        let t4 = &t1 - &t0;
        // F = D-C
        let t5 = &t3 - &t2;
        // G = D+C
        t2 += &t3;
        // H = B+A
        t0 += &t1;
        // X3 = E*F
        self.x = &t4 * &t5;
        // Y3 = G*H
        self.y = &t2 * &t0;
        // T3 = E*H
        self.t = &t4 * &t0;
        // Z3 = F*G
        self.z = &t5 * &t2;
    }
}

impl Add<&Point> for &Point {
    type Output = Point;
    fn add(self, rhs: &Point) -> Self::Output {
        let mut point = self.clone();
        point += rhs;
        point
    }
}

impl SubAssign<&Point> for Point {
    fn sub_assign(&mut self, rhs: &Point) {
        // A = (Y1-X1)*(Y2-X2)
        let mut t0 = &self.y - &self.x;
        let mut t1 = &rhs.y + &rhs.x;
        t0 *= &t1;
    
        // B = (Y1+X1)*(Y2+X2)
        t1 = &self.y + &self.x;
        let mut t2 = &rhs.y - &rhs.x;
        t1 *= &t2;

        // C = T1*2*d*T2
        t2 = &Fe::ED25519_D2 * &rhs.t;
        t2 *= &self.t;
        t2 = -&t2;

        // D = Z1*2*Z2
        let mut t3 = &rhs.z + &rhs.z;
        t3 *= &self.z;

        // E = B-A
        let t4 = &t1 - &t0;
        // F = D-C
        let t5 = &t3 - &t2;
        // G = D+C
        t2 += &t3;
        // H = B+A
        t0 += &t1;
        // X3 = E*F
        self.x = &t4 * &t5;
        // Y3 = G*H
        self.y = &t2 * &t0;
        // T3 = E*H
        self.t = &t4 * &t0;
        // Z3 = F*G
        self.z = &t5 * &t2;
    }
}

impl TryFrom<&[u8; 32]> for Point {
    type Error = PointError;

    fn try_from(value: &[u8; 32]) -> Result<Self, PointError> {
        let mut h = Point::ZERO;
        h.y = Fe::from_bytes(value);
        h.z = Fe::ONE;
        let mut u = h.y.sqr();
        let mut v = &u * &Fe::ED25519_D;
        u -= &h.z; // u = y^2-1
        v += &h.z; // v = dy^2+1

        h.x = &u * &v;
        h.x = h.x.pow22523();
        h.x = &u * &h.x; // u((uv)^((q-5)/8))
    
        let mut vxx = h.x.sqr();
        vxx *= &v;
        let m_root_check = &vxx - &u; // vx^2-u
        let p_root_check = &vxx + &u; // vx^2+u
        let has_m_root = m_root_check.is_zero() as u64;
        let has_p_root = p_root_check.is_zero() as u64;
        let x_sqrtm1 = &h.x * &Fe::SQRTM1; // x*sqrt(-1)
        h.x.cmov(&x_sqrtm1, 1 ^ has_m_root);

        let negx = -&h.x;
        let cond = h.x.is_negative() as u64 ^ (value[31] >> 7) as u64;
        h.x.cmov(&negx, cond);
        h.t = &h.x * &h.y;

        match has_m_root | has_p_root {
            1 => Ok(h),
            _ => Err(PointError),
        }
    }
}

fn point_is_canonical(s: &[u8; 32]) -> bool {
    let mut c = (s[31] & 0x7f) ^ 0x7f;
    for i in (1..=30).rev() {
        c |= s[i] ^ 0xff;
    }
    c = ((c as isize - 1) >> 8) as u8;
    let d = ((0xed - 1 - s[0] as isize) >> 8) as u8;

    (c & d & 1) == 0
}

fn equal(b: i8, c: i8) -> u64 {
    let ub = b as u8;
    let uc = c as u8;
    let x = ub ^ uc;       // 0: yes; 1..255: no
    let mut y = x as u32;  // 0: yes; 1..255: no
    y = y.wrapping_sub(1); // 4294967295: yes; 0..254: no
    (y >> 31) as u64       // 1: yes; 0: no
}

fn negative(b: i8) -> u8 {
    // 18446744073709551361..18446744073709551615: yes; 0..255: no
    (b as u64 >> 63) as u8 // 1: yes; 0: no
}

const BLOCKLIST: [[u8; 32]; 7] = [
    // 0 (order 4)
    [0u8; 32],
    // 1 (order 1)
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ],
    // 2707385501144840649318225287225658788936804267575313519463743609750303402022
    // (order 8)
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
        0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
        0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
        0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05
    ],
    // 55188659117513257062467267217118295137698188065244968500265048394206261417927
    // (order 8)
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
        0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
        0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
        0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a
    ],
    // p-1 (order 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    ],
    // p (=0, order 4)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    ],
    // p+1 (=1, order 1)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    ]
];

pub(crate) fn mont_has_small_order(s: &[u8; 32]) -> bool {
    let mut c = [0u8; 7];
    for (j, &sv) in s.iter().enumerate().take(31) {
        for i in 0.. 7 {
            c[i] |= sv ^ BLOCKLIST[i][j];
        }
    }
    for (cv, blocked) in c.iter_mut().zip(BLOCKLIST.iter()) {
        *cv |= (s[31] & 0x7f) ^ blocked[31];
    }

    let mut k = 0_usize;
    for cv in &c {
        k |= *cv as usize - 1;
    }

    ((k >> 8) & 1) == 1
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::Point;

    #[test]
    fn test_point_add() {
        let point = Point::try_from(
            &hex!("7e875846a2bfb6e4cc1d7c290fd1d128953aa92a7089278ec002d0690316dc3e")
        ).unwrap_or(Point::ZERO);
        let expected = hex!("e4b9faf10fe369d9e02e4b2f28fc38e5ba91dbb7d7d3584d2fe01a810b44b744");
        let point2 = point.dbl();

        assert_eq!(expected, point2.bytes());
    }
}
