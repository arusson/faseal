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

use crate::ml_dsa::{
    GAMMA_2,
    QINV,
    MLDSA_Q
};

// FIPS 204, algorithm 49
// Computes a*2^(-32) mod q
pub(crate) fn fq_mont_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    ((a - (t as i64) * (MLDSA_Q as i64)) >> 32) as i32
}

// Reduces an integer in [-q, q]
pub(crate) fn fq_barrett_reduce(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * MLDSA_Q
}

// FIPS 204, algorithm 36
pub(crate) fn fq_decompose(mut r: i32) -> (i32, i32) {
    r += (r >> 31) & MLDSA_Q; // make the coefficient in [0, q-1] first
    
    // We have 2*gamma_2 = 2^9*1023
    // First r is divided by 2^7, then by 4*1023 using Barrett multiplier 1025 ≈ 2^22/(4*1023)
    let mut r1 = (r + 127) >> 7;
    r1 = (r1 * 1025 + (1 << 21)) >> 22;
    r1 &= 0xf;

    let mut r0 = r - r1 * 2 * GAMMA_2;
    r0 -= (((MLDSA_Q - 1)/2 - r0) >> 31) & MLDSA_Q;
    
    (r1, r0)
}
