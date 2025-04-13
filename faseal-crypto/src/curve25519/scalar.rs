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

macro_rules! load_3 {
    ($src:expr) => {
        $src[0] as u64 | ($src[1] as u64) << 8 | ($src[2] as u64) << 16
    };
}

macro_rules! load_4 {
    ($src:expr) => {
        $src[0] as u64 | ($src[1] as u64) << 8 | ($src[2] as u64) << 16 | ($src[3] as u64) << 24
    };
}

pub(crate) fn scalar_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let a0 : i64 = 2097151 & load_3!(a[..3]) as i64;
    let a1 : i64 = 2097151 & (load_4!(a[2..6]) >> 5) as i64;
    let a2 : i64 = 2097151 & (load_3!(a[5..8]) >> 2) as i64;
    let a3 : i64 = 2097151 & (load_4!(a[7..11]) >> 7) as i64;
    let a4 : i64 = 2097151 & (load_4!(a[10..14]) >> 4) as i64;
    let a5 : i64 = 2097151 & (load_3!(a[13..16]) >> 1) as i64;
    let a6 : i64 = 2097151 & (load_4!(a[15..19]) >> 6) as i64;
    let a7 : i64 = 2097151 & (load_3!(a[18..21]) >> 3) as i64;
    let a8 : i64 = 2097151 & load_3!(a[21..24]) as i64;
    let a9 : i64 = 2097151 & (load_4!(a[23..27]) >> 5) as i64;
    let a10: i64 = 2097151 & (load_3!(a[26..29]) >> 2) as i64;
    let a11: i64 = (load_4!(a[28..]) >> 7)  as i64;

    let b0 : i64 = 2097151 & load_3!(b[..3]) as i64;
    let b1 : i64 = 2097151 & (load_4!(b[2..6]) >> 5) as i64;
    let b2 : i64 = 2097151 & (load_3!(b[5..8]) >> 2) as i64;
    let b3 : i64 = 2097151 & (load_4!(b[7..11]) >> 7) as i64;
    let b4 : i64 = 2097151 & (load_4!(b[10..14]) >> 4) as i64;
    let b5 : i64 = 2097151 & (load_3!(b[13..16]) >> 1) as i64;
    let b6 : i64 = 2097151 & (load_4!(b[15..19]) >> 6) as i64;
    let b7 : i64 = 2097151 & (load_3!(b[18..21]) >> 3) as i64;
    let b8 : i64 = 2097151 & load_3!(b[21..24]) as i64;
    let b9 : i64 = 2097151 & (load_4!(b[23..27]) >> 5) as i64;
    let b10: i64 = 2097151 & (load_3!(b[26..29]) >> 2) as i64;
    let b11: i64 = (load_4!(b[28..]) >> 7)  as i64;

    let c0 : i64 = 2097151 & load_3!(c[..3]) as i64;
    let c1 : i64 = 2097151 & (load_4!(c[2..6]) >> 5) as i64;
    let c2 : i64 = 2097151 & (load_3!(c[5..8]) >> 2) as i64;
    let c3 : i64 = 2097151 & (load_4!(c[7..11]) >> 7) as i64;
    let c4 : i64 = 2097151 & (load_4!(c[10..14]) >> 4) as i64;
    let c5 : i64 = 2097151 & (load_3!(c[13..16]) >> 1) as i64;
    let c6 : i64 = 2097151 & (load_4!(c[15..19]) >> 6) as i64;
    let c7 : i64 = 2097151 & (load_3!(c[18..21]) >> 3) as i64;
    let c8 : i64 = 2097151 & load_3!(c[21..24]) as i64;
    let c9 : i64 = 2097151 & (load_4!(c[23..27]) >> 5) as i64;
    let c10: i64 = 2097151 & (load_3!(c[26..29]) >> 2) as i64;
    let c11: i64 = (load_4!(c[28..]) >> 7)  as i64;

    let mut s0 = c0 + a0 * b0;
    let mut s1 = c1 + a0 * b1 + a1 * b0;
    let mut s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    let mut s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    let mut s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    let mut s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    let mut s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    let mut s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    let mut s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 
        + a8 * b0;
    let mut s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2
        + a8 * b1 + a9 * b0;
    let mut s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4
        + a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0;
    let mut s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5
        + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0;
    let mut s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4
        + a9 * b3 + a10 * b2 + a11 * b1;
    let mut s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4
        + a10 * b3 + a11 * b2;
    let mut s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4
        + a11 * b3;
    let mut s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    let mut s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    let mut s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    let mut s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    let mut s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    let mut s20 = a9 * b11 + a10 * b10 + a11 * b9;
    let mut s21 = a10 * b11 + a11 * b10;
    let mut s22 = a11 * b11;
    let mut s23 = 0i64;

    let mut carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 * (1 << 21);
    let mut carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 * ( 1 << 21);
    let mut carry4 = (s4 +  (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 * ( 1 << 21);
    let mut carry6 = (s6 +  (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * ( 1 << 21);
    let mut carry8 = (s8 +  (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * ( 1 << 21);
    let mut carry10 = (s10 +  (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 * ( 1 << 21);
    let mut carry12 = (s12 +  (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 * ( 1 << 21);
    let mut carry14 = (s14 +  (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 * ( 1 << 21);
    let mut carry16 = (s16 +  (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 * ( 1 << 21);
    let carry18 = (s18 +  (1 << 20)) >> 21;
    s19 += carry18;
    s18 -= carry18 * ( 1 << 21);
    let carry20 = (s20 +  (1 << 20)) >> 21;
    s21 += carry20;
    s20 -= carry20 * ( 1 << 21);
    let carry22 = (s22 +  (1 << 20)) >> 21;
    s23 += carry22;
    s22 -= carry22 * ( 1 << 21);

    let mut carry1 = (s1 +  (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 * ( 1 << 21);
    let mut carry3 = (s3 +  (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 * ( 1 << 21);
    let mut carry5 = (s5 +  (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 * ( 1 << 21);
    let mut carry7 = (s7 +  (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * ( 1 << 21);
    let mut carry9 = (s9 +  (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * ( 1 << 21);
    let mut carry11 = (s11 +  (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * ( 1 << 21);
    let mut carry13 = (s13 +  (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 * ( 1 << 21);
    let mut carry15 = (s15 +  (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 * ( 1 << 21);
    let carry17 = (s17 +  (1 << 20)) >> 21;
    s18 += carry17;
    s17 -= carry17 * ( 1 << 21);
    let carry19 = (s19 +  (1 << 20)) >> 21;
    s20 += carry19;
    s19 -= carry19 * ( 1 << 21);
    let carry21 = (s21 +  (1 << 20)) >> 21;
    s22 += carry21;
    s21 -= carry21 * ( 1 << 21);

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;

    carry6 = (s6 +  (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * ( 1 << 21);
    carry8 = (s8 +  (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * ( 1 << 21);
    carry10 = (s10 +  (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 * ( 1 << 21);
    carry12 = (s12 +  (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 * ( 1 << 21);
    carry14 = (s14 +  (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 * ( 1 << 21);
    carry16 = (s16 +  (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 * ( 1 << 21);

    carry7 = (s7 +  (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * ( 1 << 21);
    carry9 = (s9 +  (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * ( 1 << 21);
    carry11 = (s11 +  (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * ( 1 << 21);
    carry13 = (s13 +  (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 * ( 1 << 21);
    carry15 = (s15 +  (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 * ( 1 << 21);

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 +  (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 * ( 1 << 21);
    carry2 = (s2 +  (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 * ( 1 << 21);
    carry4 = (s4 +  (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 * ( 1 << 21);
    carry6 = (s6 +  (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * ( 1 << 21);
    carry8 = (s8 +  (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * ( 1 << 21);
    carry10 = (s10 +  (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 * ( 1 << 21);

    carry1 = (s1 +  (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 * ( 1 << 21);
    carry3 = (s3 +  (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 * ( 1 << 21);
    carry5 = (s5 +  (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 * ( 1 << 21);
    carry7 = (s7 +  (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * ( 1 << 21);
    carry9 = (s9 +  (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * ( 1 << 21);
    carry11 = (s11 +  (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * ( 1 << 21);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 * ( 1 << 21);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 * ( 1 << 21);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 * ( 1 << 21);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 * ( 1 << 21);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 * ( 1 << 21);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 * ( 1 << 21);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 * ( 1 << 21);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 * ( 1 << 21);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 * ( 1 << 21);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 * ( 1 << 21);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 * ( 1 << 21);
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 * ( 1 << 21);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 * ( 1 << 21);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 * ( 1 << 21);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 * ( 1 << 21);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 * ( 1 << 21);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 * ( 1 << 21);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 * ( 1 << 21);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 * ( 1 << 21);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 * ( 1 << 21);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 * ( 1 << 21);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 * ( 1 << 21);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 * ( 1 << 21);

    let mut s = [0u8; 32];
    s[0]  = s0 as u8;
    s[1]  = (s0 >> 8) as u8;
    s[2]  = ((s0 >> 16) | (s1 * ( 1 << 5))) as u8;
    s[3]  = (s1 >> 3) as u8;
    s[4]  = (s1 >> 11) as u8;
    s[5]  = ((s1 >> 19) | (s2 * ( 1 << 2))) as u8;
    s[6]  = (s2 >> 6) as u8;
    s[7]  = ((s2 >> 14) | (s3 * ( 1 << 7))) as u8;
    s[8]  = (s3 >> 1) as u8;
    s[9]  = (s3 >> 9) as u8;
    s[10] = ((s3 >> 17) | (s4 * ( 1 << 4))) as u8;
    s[11] = (s4 >> 4) as u8;
    s[12] = (s4 >> 12) as u8;
    s[13] = ((s4 >> 20) | (s5 * ( 1 << 1))) as u8;
    s[14] = (s5 >> 7) as u8;
    s[15] = ((s5 >> 15) | (s6 * ( 1 << 6))) as u8;
    s[16] = (s6 >> 2) as u8;
    s[17] = (s6 >> 10) as u8;
    s[18] = ((s6 >> 18) | (s7 * ( 1 << 3))) as u8;
    s[19] = (s7 >> 5) as u8;
    s[20] = (s7 >> 13) as u8;
    s[21] = s8 as u8;
    s[22] = (s8 >> 8) as u8;
    s[23] = ((s8 >> 16) | (s9 * ( 1 << 5))) as u8;
    s[24] = (s9 >> 3) as u8;
    s[25] = (s9 >> 11) as u8;
    s[26] = ((s9 >> 19) | (s10 * ( 1 << 2))) as u8;
    s[27] = (s10 >> 6) as u8;
    s[28] = ((s10 >> 14) | (s11 * ( 1 << 7))) as u8;
    s[29] = (s11 >> 1) as u8;
    s[30] = (s11 >> 9) as u8;
    s[31] = (s11 >> 17) as u8;
    s
}

// Input:
// s[0]+256*s[1]+...+256^63*s[63] = s
//
// Output:
// s[0]+256*s[1]+...+256^31*s[31] = s mod l
// where l = 2^252 + 27742317777372353535851937790883648493.
// Overwrites s in place.
pub(crate) fn scalar_reduce(s: &[u8; 64]) -> [u8; 32] {
    let mut s0  = (2097151 & load_3!(s[..3])) as i64;
    let mut s1  = (2097151 & (load_4!(s[2..6]) >> 5)) as i64;
    let mut s2  = (2097151 & (load_3!(s[5..8]) >> 2)) as i64;
    let mut s3  = (2097151 & (load_4!(s[7..11]) >> 7)) as i64;
    let mut s4  = (2097151 & (load_4!(s[10..14]) >> 4)) as i64;
    let mut s5  = (2097151 & (load_3!(s[13..16]) >> 1)) as i64;
    let mut s6  = (2097151 & (load_4!(s[15..19]) >> 6)) as i64;
    let mut s7  = (2097151 & (load_3!(s[18..21]) >> 3)) as i64;
    let mut s8  = (2097151 & load_3!(s[21..24])) as i64;
    let mut s9  = (2097151 & (load_4!(s[23..27]) >> 5)) as i64;
    let mut s10 = (2097151 & (load_3!(s[26..29]) >> 2)) as i64;
    let mut s11 = (2097151 & (load_4!(s[28..32]) >> 7)) as i64;
    let mut s12 = (2097151 & (load_4!(s[31..35]) >> 4)) as i64;
    let mut s13 = (2097151 & (load_3!(s[34..37]) >> 1)) as i64;
    let mut s14 = (2097151 & (load_4!(s[36..40]) >> 6)) as i64;
    let mut s15 = (2097151 & (load_3!(s[39..42]) >> 3)) as i64;
    let mut s16 = (2097151 & load_3!(s[42..45])) as i64;
    let mut s17 = (2097151 & (load_4!(s[44..48]) >> 5)) as i64;
    let s18     = (2097151 & (load_3!(s[47..50]) >> 2)) as i64;
    let s19     = (2097151 & (load_4!(s[49..53]) >> 7)) as i64;
    let s20     = (2097151 & (load_4!(s[52..56]) >> 4)) as i64;
    let s21     = (2097151 & (load_3!(s[55..58]) >> 1)) as i64;
    let s22     = (2097151 & (load_4!(s[57..61]) >> 6)) as i64;
    let s23     = (load_4!(s[60..]) >> 3) as i64;
 
    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;

    s9  += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;

    s8  += s20 * 666643;
    s9  += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;

    s7  += s19 * 666643;
    s8  += s19 * 470296;
    s9  += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;

    s6  += s18 * 666643;
    s7  += s18 * 470296;
    s8  += s18 * 654183;
    s9  -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;

    let mut carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    let mut carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    let mut carry10 = (s10 + (1 << 20) as i64) >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);
    let carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 * (1 << 21);
    let carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 * (1 << 21);
    let carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 * (1 << 21);

    let mut carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    let mut carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    let mut carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * (1 << 21);
    let carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 * (1 << 21);
    let carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 * (1 << 21);

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;
 
    let mut carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 * (1 << 21);
    let mut carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 * (1 << 21);
    let mut carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 * ( 1 << 21);
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * ( 1 << 21);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * ( 1 << 21);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 * ( 1 << 21);
 
    let mut carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 * (1 << 21);
    let mut carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 * (1 << 21);
    let mut carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 * (1 << 21);
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * (1 << 21);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;
 
    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 * (1 << 21);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 * (1 << 21);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 * (1 << 21);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 * (1 << 21);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 * (1 << 21);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 * (1 << 21);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 * (1 << 21);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
 
    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 * (1 << 21);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 * (1 << 21);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 * (1 << 21);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 * (1 << 21);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 * (1 << 21);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 * (1 << 21);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);
 
    let mut s = [0u8; 32];
    s[0]  = s0 as u8;
    s[1]  = (s0 >> 8) as u8;
    s[2]  = ((s0 >> 16) | (s1 * (1 << 5))) as u8;
    s[3]  = (s1 >> 3) as u8;
    s[4]  = (s1 >> 11) as u8;
    s[5]  = ((s1 >> 19) | (s2 * (1 << 2))) as u8;
    s[6]  = (s2 >> 6) as u8;
    s[7]  = ((s2 >> 14) | (s3 * (1 << 7))) as u8;
    s[8]  = (s3 >> 1) as u8;
    s[9]  = (s3 >> 9) as u8;
    s[10] = ((s3 >> 17) | (s4 * (1 << 4))) as u8;
    s[11] = (s4 >> 4) as u8;
    s[12] = (s4 >> 12) as u8;
    s[13] = ((s4 >> 20) | (s5 * (1 << 1))) as u8;
    s[14] = (s5 >> 7) as u8;
    s[15] = ((s5 >> 15) | (s6 * (1 << 6))) as u8;
    s[16] = (s6 >> 2) as u8;
    s[17] = (s6 >> 10) as u8;
    s[18] = ((s6 >> 18) | (s7 * (1 << 3))) as u8;
    s[19] = (s7 >> 5) as u8;
    s[20] = (s7 >> 13) as u8;
    s[21] = s8 as u8;
    s[22] = (s8 >> 8) as u8;
    s[23] = ((s8 >> 16) | (s9 * (1 << 5))) as u8;
    s[24] = (s9 >> 3) as u8;
    s[25] = (s9 >> 11) as u8;
    s[26] = ((s9 >> 19) | (s10 * (1 << 2))) as u8;
    s[27] = (s10 >> 6) as u8;
    s[28] = ((s10 >> 14) | (s11 * (1 << 7))) as u8;
    s[29] = (s11 >> 1) as u8;
    s[30] = (s11 >> 9) as u8;
    s[31] = (s11 >> 17) as u8;
    s
 }
 
 pub(crate) fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    // 2^252+27742317777372353535851937790883648493
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    ];
    let mut c = 0_isize;
    let mut n = 1_isize;

    for (&a, &b) in s.iter().rev().zip(l.iter().rev()) {
        c |= ((a as isize - b as isize) >> 8) & n;
        n &= ((a ^ b) as isize - 1) >> 8;
    }
    c != 0
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::{scalar_muladd, scalar_reduce};

    #[test]
    fn test_scalar_muladd() {
        let k1 = hex!("0fae3bf802a1585f2d6fc47bb4048f849a2ac8f18bd55fc1b183366629eee00a");
        let k2 = hex!("c5eb60e578eba1cc09db4ebff8dc2f8b83904bb793e338613ac974ad24174a03");
        let k3 = hex!("a537be27801195106727ee313ed1f11fb2a65cc370986d142881c9f963253b01");
        let expected_k4 = hex!("fface454fc6b232bfaf658cfbeb42be327674d685257c129d4481cc9ef03a008");
        let k4 = scalar_muladd(&k1, &k2, &k3);
        assert_eq!(k4, expected_k4);
    }

    #[test]
    fn test_scalar_reduce() {
        let k = hex!(
            "7b41ea2c571c0a416af15d56dfb7b35a698164afeea7657942814250fdafa1d8
            f0a930938c59b449927161a92c4f6c2a78b9f4095212650ce729f60bc7253f13"
        );
        let k_red_expected = hex!(
            "0cf005ad36842534f8ec940a7709d316f1af56cef4253a23012ff09956f0c203"
        );
        let k_red = scalar_reduce(&k);
        assert_eq!(&k_red, &k_red_expected);
    }
}
