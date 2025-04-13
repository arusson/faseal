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
    hashes::sha3::Sha3_512,
    ml_kem::{
        KYBER_K,
        poly::Poly,
        polyvec::PolyVec
    }
};

pub(crate) const PKE_CT_LEN: usize = 1088;
pub(crate) const PKE_PK_LEN: usize = 1184;
pub(crate) const PKE_SK_LEN: usize = 1152;

pub(crate) fn k_pke_keygen(
    d: &[u8; 32],
    ek_pke: &mut [u8; PKE_PK_LEN],
    dk_pke: &mut [u8; PKE_SK_LEN]
) {
    let mut rho_theta = Sha3_512::hash(&[d, &[KYBER_K as u8]]);

    // generate matrix Â
    let mut a = [PolyVec::ZERO; KYBER_K];
    for (i, row) in a.iter_mut().enumerate() {
        for j in 0..KYBER_K {
            row.0[j] = Poly::sample_ntt(rho_theta[..32].try_into().unwrap(), i as u8, j as u8);
        }
    }

    // generate s and e
    let theta = &rho_theta[32..64];
    let mut n = 0;
    let mut s = PolyVec::ZERO;
    for poly in s.0.iter_mut() {
        *poly = Poly::sample_cbd(theta.try_into().unwrap(), n);
        poly.ntt();
        poly.reduce();
        n += 1;
    }
    let mut e = PolyVec::ZERO;
    for poly in e.0.iter_mut() {
        *poly = Poly::sample_cbd(theta.try_into().unwrap(), n);
        poly.ntt();
        poly.reduce();
        n += 1;
    }

    // hat(t) = Â*ŝ + ê
    let mut t = PolyVec::ZERO;
    for (tpoly, arow) in t.0.iter_mut().zip(a.iter()) {
        *tpoly = arow.mul_mont(&s);
        tpoly.mont();
    }
    t.radd(&e);
    t.reduce();
    e.zeroize();

    // packing
    t.pack_bytes(ek_pke[..PolyVec::LEN].as_mut().try_into().unwrap());
    ek_pke[PolyVec::LEN..PKE_PK_LEN].copy_from_slice(&rho_theta[..32]);
    rho_theta.zeroize();

    s.pack_bytes(dk_pke);
    s.zeroize();
}

pub(crate) fn k_pke_encrypt(
    ek_pke: &[u8; PKE_PK_LEN],
    msg: &[u8; 32],
    r: &[u8; 32],
    ct: &mut [u8; PKE_CT_LEN]
) {
    let t = PolyVec::from_bytes(&ek_pke[..PolyVec::LEN].try_into().unwrap());

    // generate Â^T
    let rho = &ek_pke[PolyVec::LEN..];
    let mut at = [PolyVec::ZERO; KYBER_K];
    for (i, row) in at.iter_mut().enumerate() {
        for j in 0..KYBER_K {
            row.0[j] = Poly::sample_ntt(rho.try_into().unwrap(), j as u8, i as u8);
        }
    }

    // generate y, e_1 vectors, and e_2
    let mut n = 0;
    let mut y = PolyVec::ZERO;
    for poly in y.0.iter_mut() {
        *poly = Poly::sample_cbd(r, n);
        poly.ntt();
        poly.reduce();
        n += 1;
    }

    let mut e1 = PolyVec::ZERO;
    for poly in e1.0.iter_mut() {
        *poly = Poly::sample_cbd(r, n);
        n += 1;
    }

    let mut e2 = Poly::sample_cbd(r, n);

    // u = NTT^-1(Â^t * ŷ) + e_1
    let mut u = PolyVec::ZERO;
    for (upoly, arow) in u.0.iter_mut().zip(at.iter()) {
        *upoly = arow.mul_mont(&y);
        upoly.inv_ntt();
    }
    u.radd(&e1);
    u.reduce();
    e1.zeroize();

    // v = NTT^-1(hat(t)^T * ŷ) + e2 + µ
    let mut mu = Poly::from_msg(msg);
    let mut v = t.mul_mont(&y);
    v.inv_ntt();
    v.radd(&e2);
    v.radd(&mu);
    v.reduce();
    y.zeroize();
    e2.zeroize();
    mu.zeroize();

    // pack bytes
    u.compress(ct[..PolyVec::COMPRESSED_LEN].as_mut().try_into().unwrap());
    v.compress(ct[PolyVec::COMPRESSED_LEN..].as_mut().try_into().unwrap());
}

pub(crate) fn k_pke_decrypt(c: &[u8; PKE_CT_LEN], sk: &[u8; PKE_SK_LEN], m: &mut [u8; 32]) {
    let mut u = PolyVec::decompress(c[..PolyVec::COMPRESSED_LEN].try_into().unwrap());
    let v = Poly::decompress(c[PolyVec::COMPRESSED_LEN..].try_into().unwrap());
    let mut s = PolyVec::from_bytes(sk);

    // NTT(u)
    for poly in u.0.iter_mut() {
        poly.ntt();
        poly.reduce();
    }

    // v - NTT^-1(ŝ * NTT(u))
    let mut w = s.mul_mont(&u);
    w.inv_ntt();
    w.lsub(&v);
    w.reduce();
    s.zeroize();

    // convert to buffer
    *m = w.to_msg();
    w.zeroize();
}
