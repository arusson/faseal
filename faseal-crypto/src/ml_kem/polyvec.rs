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

use crate::ml_kem::{
    MLKEM_K,
    MLKEM_Q,
    MLKEM_Q32,
    poly::Poly,
    fq::fq_simple_reduce
};

#[derive(Clone)]
pub(crate) struct PolyVec(pub(crate) [Poly; MLKEM_K]);

impl Zeroize for PolyVec {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl PolyVec {
    pub(crate) const LEN: usize = Poly::LEN * MLKEM_K;
    pub(crate) const COMPRESSED_LEN: usize = 960;
    pub(crate) const ZERO: Self = Self([Poly::ZERO; MLKEM_K]);

    pub(crate) fn mul(&self, rhs: &Self) -> Poly {
        let mut r = self.0[0].mul(&rhs.0[0]);
        for i in 1..MLKEM_K {
            let t = self.0[i].mul(&rhs.0[i]);
            r.radd(&t);
        }
        // This applies a Barrett reduction and is sufficient:
        // After a polynomial multiplication in NTT, coefficients are in [-(q-1), q-1].
        // The accumulation extends this interval to at most [-4(q-1), 4(q-1)] (for ML-KEM-1024),
        // so it stays within bounds such that the Barrett reduction results with a full
        // reduction in [-1664, 1664].
        r.reduce();
        r
    }

    // Does not reduce coefficients of each polynomial.
    pub(crate) fn radd(&mut self, rhs: &Self) {
        for (rpoly, apoly) in self.0.iter_mut().zip(rhs.0.iter()) {
            rpoly.radd(apoly);
        }
    }

    pub(crate) fn reduce(&mut self) {
        for rpoly in self.0.iter_mut() {
            rpoly.reduce();
        }
    }

    pub(crate) fn pack_bytes(&self, buffer: &mut [u8; Self::LEN]) {
        for (poly, buf) in self.0.iter().zip(buffer.chunks_exact_mut(Poly::LEN)) {
            poly.pack_bytes(buf.try_into().unwrap());
        }
    }

    pub(crate) fn from_bytes(buffer: &[u8; Self::LEN]) -> Self {
        let mut polyvec = Self::ZERO;
        for (poly, src) in polyvec.0.iter_mut().zip(buffer.chunks_exact(Poly::LEN)) {
            *poly = Poly::from_bytes(src.try_into().unwrap());
        }
        polyvec
    }

    pub(crate) fn compress(&self, buffer: &mut [u8; Self::COMPRESSED_LEN]) {
        for (poly, chunk) in self.0.iter().zip(
            buffer.chunks_exact_mut(Self::COMPRESSED_LEN/MLKEM_K)
        ) {
            for (coefs, dst) in poly.0.chunks_exact(4).zip(chunk.chunks_exact_mut(5)) {
                let mut t = [0u16; 4];
                for (tt, &coef) in t.iter_mut().zip(coefs.iter()) {
                    *tt = (coef + ((coef >> 15) & MLKEM_Q)) as u16;
                    let mut d0 = (*tt as u64) << 10;
                    d0 += 1665;
                    d0 *= 1_290_167;
                    d0 >>= 32;
                    *tt = (d0 & 0x3ff) as u16;
                }

                dst[0]  = t[0] as u8;
                dst[1]  = (t[0] >> 8)  as u8 | (t[1] << 2) as u8;
                dst[2]  = (t[1] >> 6)  as u8 | (t[2] << 4) as u8;
                dst[3]  = (t[2] >> 4)  as u8 | (t[3] << 6) as u8;
                dst[4]  = (t[3] >> 2) as u8;
            }
        }
    }

    pub(crate) fn decompress(buffer: &[u8; Self::COMPRESSED_LEN]) -> Self {
        let mut polyvec = Self::ZERO;
        for (poly, chunk) in polyvec.0.iter_mut().zip(
            buffer.chunks_exact(Self::COMPRESSED_LEN/MLKEM_K)
        ) {
            for (coefs, src) in poly.0.chunks_exact_mut(4).zip(chunk.chunks_exact(5)) {
                let mut t = [0u16; 4];
                t[0] = (src[0] as u16) | ((src[1] as u16) << 8);
                t[1] = ((src[1] as u16) >> 2) | ((src[2] as u16) << 6);
                t[2] = ((src[2] as u16) >> 4) | ((src[3] as u16) << 4);
                t[3] = ((src[3] as u16) >> 6) | ((src[4] as u16) << 2);

                for (coef, &tt) in coefs.iter_mut().zip(t.iter()) {
                    *coef = ((((tt & 0x3ff) as i32) * MLKEM_Q32 + 512) >> 10) as i16;
                    *coef = fq_simple_reduce(*coef);
                }
            }
        }
        polyvec
    }
}

#[cfg(test)]
mod tests {
    use super::PolyVec;
    use rand::RngCore;

    #[test]
    fn test_ml_kem_polyvec_compress() {
        let mut buf1 = [0u8; PolyVec::COMPRESSED_LEN];
        rand::rng().fill_bytes(&mut buf1);

        let polyvec = PolyVec::decompress(&buf1);
        let mut buf2 = [0u8; PolyVec::COMPRESSED_LEN];
        polyvec.compress(&mut buf2);
        assert_eq!(buf1, buf2);
    }
}
