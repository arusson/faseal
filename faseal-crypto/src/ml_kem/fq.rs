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

use crate::ml_kem::{
    MLKEM_Q,
    MLKEM_Q32
};

// Reduces an integer:
// - in [-1681, 1681]: if the input is the result of a multiplication of two reduced integers,
//                     and it needs further reduction (with `simple_reduce()`).
// - in [-1664, 1664]: if the input is in [-2^14, 2^14].
pub(crate) fn fq_barrett_reduce(a: i32) -> i16 {
    let mut t = ((20159 * (a as i64) + (1 << 25)) >> 26) as i32;
    t = t.wrapping_mul(MLKEM_Q32);
    a.wrapping_sub(t) as i16
}

// Reduces an integer from [-q + 1, q - 1] into [-(q-1)/2, (q-1)/2].
pub(crate) fn fq_simple_reduce(a: i16) -> i16 {
    dbg!(a);
    assert!(a <= 3328);
    assert!(a >= -3328);
    let b = a + ((a >> 15) & MLKEM_Q);
    let c = b - 1665;
    b - (!(c >> 15) & MLKEM_Q)
}

// Multiplication modulo 3329 with reduction in [-1664, 1664].
pub(crate) fn fq_mul(a: i16, b: i16) -> i16 {
    let d = fq_barrett_reduce((a as i32) * (b as i32));
    fq_simple_reduce(d)
}

#[cfg(test)]
mod tests {
    use super::{
        fq_barrett_reduce,
        fq_simple_reduce
    };

    #[test]
    fn test_barrett_reduce() {
        for a in -16384..=16384 {
            let c = fq_barrett_reduce(a as i32);
            assert_eq!((c.wrapping_sub(a)) % 3329, 0);
            assert!(c >= -1664);
            assert!(c <= 1664);
        }
    }

    #[test]
    fn test_simple_reduce() {
        for a in -3328..=3328 {
            let c = fq_simple_reduce(a);
            assert_eq!((c.wrapping_sub(a)) % 3329, 0);
            assert!(c >= -1664);
            assert!(c <= 1664);
        }
    }
}