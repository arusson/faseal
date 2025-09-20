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

use crate::hashes::sha3::Shake256;
use crate::ml_dsa::{
    BETA,
    GAMMA_1,
    GAMMA_2,
    LAMBDA4,
    MLDSA_K,
    MLDSA_L,
    OMEGA,
    poly::Poly,
    polyvec::{
        PolyVecK,
        PolyVecL
    },
    MlDsa65
};
use crate::traits::sigt::{
    Error,
    Result
};

const OFFSET_S1: usize = 128;
const OFFSET_S2: usize = OFFSET_S1 + Poly::ETA_LEN * MLDSA_L;
const OFFSET_T0: usize = OFFSET_S2 + Poly::ETA_LEN * MLDSA_K;
const OFFSET_Z: usize = 48;
const OFFSET_HINTS: usize = OFFSET_Z + Poly::GAMMA_LEN * MLDSA_L;

impl MlDsa65 {
    // FIPS 204, algorithm 6
    pub(crate) fn keygen_internal(
        seed: &[u8; 32],
        signing_key: &mut [u8; Self::SK_LEN],
        verifying_key: &mut [u8; Self::VK_LEN]
    ) {
        // expand seed
        let mut buf = [0u8; 128];
        Shake256::hash_into(&[seed, &[MLDSA_K as u8, MLDSA_L as u8]], &mut buf);

        // generate public matrix Â
        let rho: &[u8; 32] = buf[..32].try_into().unwrap();
        let a_hat = expand_a(rho);

        // FIPS 204, algorithm 33
        // generation of secret vectors
        let rhoprime: &[u8; 64] = &buf[32..96].try_into().unwrap();
        let mut s1 = PolyVecL::ZERO;
        for (r, poly) in s1.0.iter_mut().enumerate() {
            *poly = Poly::sample_bounded(rhoprime, [r as u8, 0]);
        }
        let mut s2 = PolyVecK::ZERO;
        for (r, poly) in s2.0.iter_mut().enumerate() {
            *poly = Poly::sample_bounded(rhoprime, [(MLDSA_L + r) as u8, 0]);
        }

        // generate public vector t = NTT^-1(Â ∘ NTT(s1)) + s2
        let mut s1_hat = s1.clone();
        s1_hat.ntt();
        let mut t1 = PolyVecK::ZERO;
        for (poly, row) in t1.0.iter_mut().zip(a_hat.iter()) {
            *poly = row.mul_mont(&s1_hat);
        }
        t1.reduce();
        t1.inv_ntt();
        t1.radd(&s2);
        s1_hat.zeroize();

        // extract (t1, t0) from t
        let mut t0 = PolyVecK::ZERO;
        for (t1poly, t0poly)  in t1.0.iter_mut().zip(t0.0.iter_mut()) {
            *t0poly = t1poly.power2round();
        }

        // FIPS 204, algorithm 22
        // pack verifying key
        verifying_key[..32].copy_from_slice(rho);
        for (chunk, poly) in verifying_key[32..].chunks_exact_mut(Poly::T1_LEN).zip(t1.0.iter()) {
            poly.pack_bytes_t1(chunk.try_into().unwrap());
        }

        // FIPS 204, algorithm 24
        // pack signing key
        signing_key[..32].copy_from_slice(rho);
        signing_key[32..64].copy_from_slice(&buf[96..]);
        Shake256::hash_into(&[verifying_key], &mut signing_key[64..128]);
        for (chunk, poly) in signing_key[OFFSET_S1..OFFSET_S2]
            .chunks_exact_mut(Poly::ETA_LEN).zip(s1.0.iter())
        {
            poly.pack_bytes_eta(chunk.try_into().unwrap());
        }
        for (chunk, poly) in signing_key[OFFSET_S2..OFFSET_T0]
            .chunks_exact_mut(Poly::ETA_LEN)
            .zip(s2.0.iter())
        {
            poly.pack_bytes_eta(chunk.try_into().unwrap());
        }
        for (chunk, poly) in signing_key[OFFSET_T0..]
            .chunks_exact_mut(Poly::T0_LEN).zip(t0.0.iter())
        {
            poly.pack_bytes_t0(chunk.try_into().unwrap());
        }
        buf.zeroize();
        s1.zeroize();
        s2.zeroize();
        t0.zeroize();
    }

    // FIPS 204, algorithm 7
    pub(crate) fn sign_internal(
        signing_key: &[u8; Self::SK_LEN],
        message: &[u8],
        rnd: &[u8; 32],
        pre: &[u8],
        ctx: &[u8]
    ) -> [u8; Self::SIG_LEN] {
        // FIPS 204, algorithm 25
        // refences to individual parts of the signing key
        let rho: &[u8; 32] = &signing_key[..32].try_into().unwrap();
        let key: &[u8; 32] = &signing_key[32..64].try_into().unwrap();
        let tr:  &[u8; 64] = &signing_key[64..128].try_into().unwrap();
        let s1_bytes: &[u8; MLDSA_L * Poly::ETA_LEN] = &signing_key[OFFSET_S1..OFFSET_S2]
            .try_into().unwrap();
        let s2_bytes: &[u8; MLDSA_K * Poly::ETA_LEN] = &signing_key[OFFSET_S2..OFFSET_T0]
            .try_into().unwrap();
        let t0_bytes: &[u8; MLDSA_K * Poly::T0_LEN] = &signing_key[OFFSET_T0..]
            .try_into().unwrap();
    
        // extract s1 in NTT form
        let mut s1 = PolyVecL::ZERO;
        for (chunk, poly) in s1_bytes.chunks_exact(Poly::ETA_LEN).zip(s1.0.iter_mut()) {
            *poly = Poly::unpack_bytes_eta(chunk.try_into().unwrap());
            poly.ntt();
        }

        // extract s2 in NTT form
        let mut s2 = PolyVecK::ZERO;
        for (chunk, poly) in s2_bytes.chunks_exact(Poly::ETA_LEN).zip(s2.0.iter_mut()) {
            *poly = Poly::unpack_bytes_eta(chunk.try_into().unwrap());
            poly.ntt();
        }

        // extract t0 in NTT form
        let mut t0 = PolyVecK::ZERO;
        for (chunk, poly) in t0_bytes.chunks_exact(Poly::T0_LEN).zip(t0.0.iter_mut()) {
            *poly = Poly::unpack_bytes_t0(chunk.try_into().unwrap());
            poly.ntt();
        }

        // generate matrix A
        let a_hat = expand_a(rho);
    
        // message representative and private random seed
        let mut mu = [0u8; 64];
        Shake256::hash_into(&[tr, pre, ctx, message], &mut mu);
        let mut rho_second = [0u8; 64];
        Shake256::hash_into(&[key, rnd, &mu], &mut rho_second);

        // rejection sampling loop
        let mut kappa = 0u16;
        let (ctilde, z, h) = loop {
            // FIPS 204, algorithm 34 (expand mask)
            let mut y = PolyVecL::ZERO;
            for poly in y.0.iter_mut() {
                *poly = Poly::sample_gamma(&rho_second, kappa.to_le_bytes());
                kappa += 1;
            }

            // w = NTT^-1(Â ∘ NTT(y))
            let mut z = y.clone();
            z.ntt();
            let mut w1 = PolyVecK::ZERO;
            for (poly, arow) in w1.0.iter_mut().zip(a_hat.iter()) {
                *poly = arow.mul_mont(&z);
            }
            w1.reduce();
            w1.inv_ntt();

            // w decomposed as (w0, w1)
            // w0 is used to apply the alternative presented in section 5.1 of "CRYSTALS-Dilithium:
            // Algorithm specifications and supporting documentation (Version 3.1)."
            // https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf.
            let mut w0 = PolyVecK::ZERO;
            for (w0poly, w1poly) in w0.0.iter_mut().zip(w1.0.iter_mut()) {
                w1poly.decompose(w0poly);
            }

            // encode w1 for commitment hash
            let mut w1packed = [0u8; MLDSA_K * Poly::W1_LEN];
            for (chunk, poly) in w1packed.chunks_exact_mut(Poly::W1_LEN).zip(w1.0.iter()) {
                poly.pack_bytes_w1(chunk.try_into().unwrap());
            }

            // commitment hash: SHAKE256(µ || w1Encode(w1), 64
            let mut ctilde = [0u8; LAMBDA4];
            Shake256::hash_into(&[&mu, &w1packed], &mut ctilde);
        
            // verifier's challenge
            let mut c = Poly::sample_in_ball(&ctilde);
            c.ntt();
    
            // NTT^-1(ĉ ∘ ŝ1)
            for (zpoly, s1poly) in z.0.iter_mut().zip(s1.0.iter()) {
                *zpoly = c.mul_mont(s1poly);
            }
            z.inv_ntt();

            // signer's response: z <- y + NTT^-1(ĉ ∘ ŝ1)
            z.radd(&y);
            z.reduce();

            // first check on the norm of z
            if !z.check_norm(GAMMA_1 - BETA) {
                continue;
            }

            // NTT^-1(ĉ ∘ ŝ2)
            let mut h = PolyVecK::ZERO;
            for (hpoly, s2poly) in h.0.iter_mut().zip(s2.0.iter()) {
                *hpoly = c.mul_mont(s2poly);
            }
            h.inv_ntt();

            // LowBits(w - NTT^-1(ĉ ∘ ŝ2))
            // w0 is used here instead of w (see comment above):
            // w0 - cs_2 is equivalent to LowBits(w - cs_2)
            w0.rsub(&h);
            w0.reduce();
            
            // second check on the norm of LowBits(w - cs_2)
            if !w0.check_norm(GAMMA_2 - BETA) {
                continue;
            }

            // NTT^-1(ĉ ∘ hat(t0))
            for (hpoly, t0poly) in h.0.iter_mut().zip(t0.0.iter()) {
                *hpoly = c.mul_mont(t0poly);
            }
            h.inv_ntt();
            h.reduce();

            // third check on the norm of ct_0
            if !h.check_norm(GAMMA_2) {
                continue;
            }

            // signer's hint
            w0.radd(&h);
            // at this point, the variable w0 corresponds to w0 - cs_2 + ct_0
            // and the altenartive method is applied for MakeHint
            let n = h.make_hint(&w0, &w1);
            // fourth check on the number of 1's in h
            if n <= OMEGA {
                y.zeroize();
                break (ctilde, z, h);
            }
        };

        s1.zeroize();
        s2.zeroize();
        t0.zeroize();
        rho_second.zeroize();
    
        // FIPS 204, algorithm 26
        // pack signature
        let mut sig = [0u8; Self::SIG_LEN];
        sig[..OFFSET_Z].copy_from_slice(&ctilde);
        for (chunk, poly) in sig[OFFSET_Z..OFFSET_HINTS]
            .chunks_exact_mut(Poly::GAMMA_LEN).zip(z.0.iter())
        {
            poly.pack_bytes_gamma(chunk.as_mut().try_into().unwrap());
        }
        
        // FIPS 204, algorithm 20
        let mut idx = 0;
        for (i, poly) in h.0.iter().enumerate() {
            for (j, &coef) in poly.0.iter().enumerate() {
                if coef != 0 {
                    sig[OFFSET_HINTS + idx] = j as u8;
                    idx += 1;
                }
            }
            sig[OFFSET_HINTS + OMEGA + i] = idx as u8;
        }
        sig
    }

    // FIPS 204, algorithm 8
    pub(crate) fn verify_internal(
        verifying_key: &[u8; Self::VK_LEN],
        message: &[u8],
        sig: &[u8; Self::SIG_LEN],
        pre: &[u8],
        ctx: &[u8],
    ) -> Result<()> {
        // FIPS 204, algorithm 23
        // unpack verifying key
        let rho: &[u8; 32] = verifying_key[..32].try_into().unwrap();
        let mut t1 = PolyVecK::ZERO;
        for (poly, chunk) in t1.0.iter_mut().zip(verifying_key[32..].chunks_exact(Poly::T1_LEN)) {
            *poly = Poly::unpack_bytes_t1(chunk.try_into().unwrap());
        }

        // FIPS 204, algorithm 27
        // unpack signature
        // - signer's commitment hash
        let ctilde: &[u8; LAMBDA4] = &sig[..LAMBDA4].try_into().unwrap();
        // - response z
        let mut z = PolyVecL::ZERO;
        for (chunk, poly) in sig[OFFSET_Z..OFFSET_HINTS]
            .chunks_exact(Poly::GAMMA_LEN).zip(z.0.iter_mut())
        {
            *poly = Poly::unpack_bytes_gamma(chunk.try_into().unwrap());
        }
        if !z.check_norm(GAMMA_1 - BETA) {
            return Err(Error::InvalidSignature);
        }
        // - hint h
        //   FIPS 204, algorithm 21
        let mut h = PolyVecK::ZERO;
        let sigh = &sig[OFFSET_HINTS..];
        let mut idx = 0;
        for i in 0..MLDSA_K {
            if (sigh[OMEGA + i] as usize) < idx || (sigh[OMEGA + i] as usize) > OMEGA {
                return Err(Error::InvalidSignature);
            }
            for j in idx..(sigh[OMEGA + i] as usize) {
                if j > idx && sigh[j] <= sigh[j - 1] {
                    return Err(Error::InvalidSignature);
                }
                h.0[i].0[sigh[j] as usize] = 1;
            }
            idx = sigh[OMEGA + i] as usize;
        }
        for &v in sigh.iter().take(OMEGA).skip(idx) {
            if v != 0 {
                return Err(Error::InvalidSignature);
            }
        }

        // generate matrix A
        let a_hat = expand_a(rho);
    
        // message representative µ
        let mut tr = [0u8; 64];
        Shake256::hash_into(&[verifying_key], &mut tr);
        let mut mu = [0u8; 64];
        Shake256::hash_into(&[&tr, pre, ctx, message], &mut mu);

        // verifier's challenge
        let mut c = Poly::sample_in_ball(ctilde);

        // compute w'_approx
        // - Â ∘ NTT(z)
        z.ntt();
        let mut w1 = PolyVecK::ZERO;
        for (poly, arow) in w1.0.iter_mut().zip(a_hat.iter()) {
            *poly = arow.mul_mont(&z);
        }

        // - NTT(c) ∘ NTT(t1 * 2^d)
        c.ntt();
        t1.shiftl();
        t1.ntt();
        for poly in t1.0.iter_mut() {
            *poly = poly.mul_mont(&c);
        }

        // - Az - ct1 * 2^d
        w1.rsub(&t1);
        w1.reduce();
        w1.inv_ntt();

        // reconstruction of signer's commitment
        w1.use_hint(&h);

        // encode w1 for commitment hash
        let mut w1packed = [0u8; MLDSA_K * Poly::W1_LEN];
        for (chunk, poly) in w1packed.chunks_exact_mut(Poly::W1_LEN).zip(w1.0.iter()) {
            poly.pack_bytes_w1(chunk.try_into().unwrap());
        }

        let mut ctilde_prime = [0u8; LAMBDA4];
        Shake256::hash_into(&[&mu, &w1packed], &mut ctilde_prime);

        if ctilde == &ctilde_prime {
            Ok(())
        }
        else {
            Err(Error::InvalidSignature)
        }
    }    
}

// FIPS 204, algorithm 32
pub(crate) fn expand_a(seed: &[u8; 32]) -> [PolyVecL; MLDSA_K] {
    let mut a_hat = [PolyVecL::ZERO; MLDSA_K];
    for (r, row) in a_hat.iter_mut().enumerate() {
        for (s, poly) in row.0.iter_mut().enumerate() {
            *poly = Poly::sample_ntt(seed, s as u8, r as u8);
        }
    }
    a_hat
}
