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
use crate::curve25519::{
    field::Fe,
    points::Point,
};

pub(crate) fn scalarmult_ed25519_base(a: &[u8; 32]) -> Point {
    let mut e = [0i8; 64];

    for (ee, &aa) in e.chunks_exact_mut(2).zip(a.iter()) {
        ee[0] = (aa & 15) as i8;
        ee[1] = ((aa >> 4) & 15) as i8;
    }

    // each e[i] is between 0 and 15
    // e[63] is between 0 and 7

    let mut carry = 0i8;
    for ee in e.iter_mut().take(63) {
        *ee += carry;
        carry = *ee + 8;
        carry >>= 4;
        *ee -= carry * (1i8 << 4);
    }
    e[63] += carry;
    // each e[i] is between -8 and 8

    let mut t = Point::ZERO;
    let mut h = Point::ZERO;
    for i in (1..64).rev() {
        t.cmov8_base(e[i]);
        h += &t;

        h = h.dbl().dbl().dbl().dbl();
    }
    t.cmov8_base(e[0]);
    h += &t;
    e.zeroize();

    h
}

pub(crate) fn scalarmult_x25519_base(n: &[u8; 32]) -> [u8; 32] {
    let mut scalar = *n;
    scalar[0]  &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    let point = scalarmult_ed25519_base(&scalar);
    scalar.zeroize();
    // Edwards to Montgomery conversion
    let tmp_x = &point.z + &point.y;
    let tmp_z = (&point.z - &point.y).invert();
    let pk = &tmp_x * &tmp_z;
    pk.bytes()
}

pub(crate) fn scalarmult_x25519(n: &[u8; 32], p: &[u8; 32]) -> [u8; 32] {
    let mut t = *n;
    t[0] &= 248;
    t[31] &= 127;
    t[31] |= 64;

    // point initialization
    // p: infinity point, (1:0) in the XZ coordinate system
    // q: the base point (x:1)
    let mut px = Fe::ONE;
    let mut pz = Fe::ZERO;
    let mut qx = Fe::from_bytes(p);
    let mut qz = Fe::ONE;
    let x = qx;

    let mut pbit = 0u64;
    let mut bit: u64;

    for i in (0..255).rev() {
        bit = ((t[i/8] >> (i & 7)) & 1) as u64;
        pbit ^= bit;
        px.cswap(&mut qx, pbit);
        pz.cswap(&mut qz, pbit);

        // ladder step
        let a = &px + &pz;
        let b = &px - &pz;
        let aa = a.sqr();
        let bb = b.sqr();
        px = &aa * &bb;
        let e = &aa - &bb;
        let mut da = &qx - &qz;
        da *= &a;
        let mut cb = &qx + &qz;
        cb *= &b;
        qx = &da + &cb;
        qx = qx.sqr();
        qz = &da - &cb;
        qz = qz.sqr();
        qz *= &x;
        pz = &e * 121666;
        pz += &bb;
        pz *= &e;

        pbit = bit;
    }
    px.cswap(&mut qx, pbit);
    pz.cswap(&mut qz, pbit);

    pz = pz.invert();
    px *= &pz;

    t.zeroize();

    px.bytes()
}

pub(crate) fn scalarmult_double(n_base: &[u8; 32], n_var: &[u8; 32], point: &Point) -> Point {
    // P + Q
    let point_sum = point + &Point::BASE_PRECOMP[0];
    let points = [&Point::BASE_PRECOMP[0], point, &point_sum];

    let mut acc = Point::ZERO;
    let mut choice: usize;
    for pos in (0..256).rev() {
        choice = ((n_base[pos / 8] >> (pos % 8)) & 1) as usize
            + 2 * ((n_var[pos / 8] >> (pos % 8)) & 1) as usize;
        acc = acc.dbl();
        match choice {
            1 => acc += points[0],
            2 => acc += points[1],
            3 => acc += points[2],
            _ => ()
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::{
        scalarmult_x25519,
        scalarmult_x25519_base
    };

    #[test]
    fn test_scalarmult_x25519() {
        // source: https://datatracker.ietf.org/doc/html/rfc7748#section-5.2
        let k = hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let base = hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let x_expected = hex!("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        let x = scalarmult_x25519(&k, &base);
        assert_eq!(x, x_expected);

        let k = hex!("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let base = hex!("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let x_expected = hex!("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        let x = scalarmult_x25519(&k, &base);
        assert_eq!(x, x_expected);
    }

    #[ignore]
    #[test]
    fn test_scalarmult_x25519_long() {
        // this test is long, so it is ignored by default
        let mut n = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        let mut base =hex!("0900000000000000000000000000000000000000000000000000000000000000");
        let expect_1 = hex!("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        let expect_1_000 = hex!("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
        let expect_1_000_000 = hex!(
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"
        );
    
        let mut res = scalarmult_x25519(&n, &base);
        assert_eq!(res, expect_1);

        for _ in 0..999 {
            base = n;
            n = res;
            res = scalarmult_x25519(&n, &base);
        }
        assert_eq!(res, expect_1_000);

        for i in 0..999_000 {
            if (i + 1) % 10000 == 0 {
                dbg!(i + 1);
            }
            base = n;
            n = res;
            res = scalarmult_x25519(&n, &base);
        }
        assert_eq!(res, expect_1_000_000);
    }

    #[test]
    fn test_scalarmult_x25519_base() {
        let k = hex!("8aed5ff130066e6945dfd0ab7c47d7ca846f9fec894cad7cc2347de566d3a002");
        let expected_x = hex!("5c4b1e25ae7d8e17cf6b8ea78125742f42682eef5a1b4992d872931b7bdb4273");
        let x = scalarmult_x25519_base(&k);
        assert_eq!(x, expected_x);
    }
}
