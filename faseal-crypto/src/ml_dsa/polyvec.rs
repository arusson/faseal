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

use crate::ml_dsa::{
    ML_DSA_K,
    ML_DSA_L,
    poly::Poly
};

#[derive(Clone)]
pub(crate) struct PolyVec<const T: usize>(pub(crate) [Poly; T]);
pub(crate) type PolyVecK = PolyVec<ML_DSA_K>;
pub(crate) type PolyVecL = PolyVec<ML_DSA_L>;

impl<const T: usize> Zeroize for PolyVec<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const T: usize> PolyVec<T> {
    pub(crate) const ZERO: Self = Self([Poly::ZERO; T]);

    pub(crate) fn ntt(&mut self) {
        for poly in self.0.iter_mut() {
            poly.ntt();
        }
    }

    pub(crate) fn inv_ntt(&mut self) {
        for poly in self.0.iter_mut() {
            poly.inv_ntt();
        }
    }

    pub(crate) fn radd(&mut self, rhs: &Self) {
        for (ac, bc) in self.0.iter_mut().zip(rhs.0.iter()) {
            ac.radd(bc);
        }
    }

    pub(crate) fn rsub(&mut self, rhs: &Self) {
        for (ac, bc) in self.0.iter_mut().zip(rhs.0.iter()) {
            ac.rsub(bc);
        }
    }

    pub(crate) fn mul_mont(&self, rhs: &Self) -> Poly {
        let mut r = self.0[0].mul_mont(&rhs.0[0]);
        for i in 1..T {
            let t = self.0[i].mul_mont(&rhs.0[i]);
            r.radd(&t);
        }
        r
    }

    pub(crate) fn reduce(&mut self) {
        for coef in self.0.iter_mut() {
            coef.reduce();
        }
    }

    pub(crate) fn check_norm(&self, norm: i32) -> bool {
        for poly in self.0.iter() {
            if !poly.check_norm(norm) {
                return false;
            }
        }
        true
    }

    pub(crate) fn make_hint(&mut self, a: &Self, b: &Self) -> usize {
        let mut s = 0;
        for (c, (ac, bc)) in self.0.iter_mut().zip(a.0.iter().zip(b.0.iter())) {
            s += c.make_hint(ac, bc);
        }
        s
    }

    pub(crate) fn shiftl(&mut self) {
        for poly in self.0.iter_mut() {
            for coef in poly.0.iter_mut() {
                *coef <<= 13;
            }
        }
    }

    pub(crate) fn use_hint(&mut self, a: &Self) {
        for (poly, apoly) in self.0.iter_mut().zip(a.0.iter()) {
            poly.use_hint(apoly);
        }
    }
}
