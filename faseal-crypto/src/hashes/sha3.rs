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

// Public struct for SHA-3 and SHAKE
pub(crate) struct Sha3_256(KeccakCore<SHA3_256_RATE>);
pub struct Sha3_512(KeccakCore<SHA3_512_RATE>);
pub(crate) struct Shake128(KeccakCore<SHAKE128_RATE>);
pub(crate) struct Shake256(KeccakCore<SHAKE256_RATE>);

// SHA-3
const SHA3_256_RATE: usize = 136;
const SHA3_256_LEN:  usize = 32;
const SHA3_512_RATE: usize = 72;
const SHA3_512_LEN:  usize = 64;

impl Sha3_256 {
    pub(crate) fn hash(input: &[&[u8]]) -> [u8; SHA3_256_LEN] {
        sha3_hash::<SHA3_256_LEN, SHA3_256_RATE>(input)
    }

    pub(crate) fn hash_into(input: &[&[u8]], output: &mut [u8; SHA3_256_LEN]) {
        sha3_hash_into::<SHA3_256_LEN, SHA3_256_RATE>(input, output);
    }
}

impl Zeroize for Sha3_256 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Sha3_512 {
    pub const HASH_LEN: usize = SHA3_512_LEN;

    pub fn init() -> Self {
        Self(KeccakCore::<SHA3_512_RATE>::init())
    }

    pub fn update(&mut self, input: &[u8]) {
        self.0.absorb(input);
    }

    pub fn finalize(&mut self) -> [u8; SHA3_512_LEN] {
        let mut output = [0u8; SHA3_512_LEN];
        self.0.finalize(0x06);
        self.0.squeeze_block();
        output.copy_from_slice(&self.0.buf[..SHA3_512_LEN]);
        output
    }

    pub fn hash(input: &[&[u8]]) -> [u8; SHA3_512_LEN] {
        sha3_hash::<SHA3_512_LEN, SHA3_512_RATE>(input)
    }
}

impl Zeroize for Sha3_512 {
    fn zeroize(&mut self) {
        self.0.state.zeroize();
    }
}

fn sha3_hash<const LEN: usize, const RATE: usize>(input: &[&[u8]]) -> [u8; LEN] {
    let mut output = [0u8; LEN];
    let mut core = KeccakCore::<RATE>::init();
    core.absorb_once(input, 0x06);
    core.squeeze_block();
    output.copy_from_slice(&core.buf[..LEN]);
    core.zeroize();
    output
}

fn sha3_hash_into<const LEN: usize, const RATE: usize>(
    input: &[&[u8]],
    output: &mut [u8; LEN]
) {
    let mut core = KeccakCore::<RATE>::init();
    core.absorb_once(input, 0x06);
    core.squeeze_block();
    output.copy_from_slice(&core.buf[..LEN]);
    core.zeroize();
}

// SHAKE
const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

impl Shake128 {
    pub(crate) fn init() -> Self {
        Self(KeccakCore::<SHAKE128_RATE>::init())
    }

    pub(crate) fn absorb(&mut self, input: &[&[u8]]) {
        self.0.absorb_once(input, 0x1f);
        self.0.squeeze_block();
    }

    pub(crate) fn squeeze(&mut self, output: &mut [u8]) {
        self.0.squeeze(output);
    }
}

impl Zeroize for Shake128 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Shake256 {
    pub(crate) fn init() -> Self {
        Self(KeccakCore::<SHAKE256_RATE>::init())
    }

    pub(crate) fn absorb(&mut self, input: &[&[u8]]) {
        self.0.absorb_once(input, 0x1f);
        self.0.squeeze_block();
    }

    pub(crate) fn squeeze(&mut self, output: &mut [u8]) {
        self.0.squeeze(output);
    }

    pub(crate) fn hash_into(input: &[&[u8]], output: &mut [u8]) {
        shake_hash_into::<SHAKE256_RATE>(input, output);
    }
}

impl Zeroize for Shake256 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

fn shake_hash_into<const RATE: usize>(input: &[&[u8]], output: &mut [u8]) {
    let mut prf = KeccakCore::<RATE>::init();
    prf.absorb_once(input, 0x1f);
    prf.squeeze_block();
    prf.squeeze(output);
    prf.zeroize();
}

// --- Keccak
const KECCAK_BLOCK_BYTE_LEN: usize = 200;
const KECCAK_BLOCK_WORD_LEN: usize = 25;

struct KeccakCore<const RATE: usize> {
    state: [u64; KECCAK_BLOCK_WORD_LEN],
    buf: [u8; KECCAK_BLOCK_BYTE_LEN],
    pos: usize,
}

const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
];

// adapted from https://github.com/PQClean/PQClean/blob/master/common/fips202.c
#[allow(non_snake_case)]
fn keccak_p(state: &mut [u64; KECCAK_BLOCK_WORD_LEN]) {
    let mut Aba = state[0];
    let mut Abe = state[1];
    let mut Abi = state[2];
    let mut Abo = state[3];
    let mut Abu = state[4];
    let mut Aga = state[5];
    let mut Age = state[6];
    let mut Agi = state[7];
    let mut Ago = state[8];
    let mut Agu = state[9];
    let mut Aka = state[10];
    let mut Ake = state[11];
    let mut Aki = state[12];
    let mut Ako = state[13];
    let mut Aku = state[14];
    let mut Ama = state[15];
    let mut Ame = state[16];
    let mut Ami = state[17];
    let mut Amo = state[18];
    let mut Amu = state[19];
    let mut Asa = state[20];
    let mut Ase = state[21];
    let mut Asi = state[22];
    let mut Aso = state[23];
    let mut Asu = state[24];

    for rc in RC.chunks_exact(2) {
        // prepareTheta
        let mut BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        let mut BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        let mut BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        let mut BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        let mut BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
    
        // thetaRhoPiChiIotaPrepareTheta(round, A, E)
        let mut Da = BCu ^ BCe.rotate_left(1);
        let mut De = BCa ^ BCi.rotate_left(1);
        let mut Di = BCe ^ BCo.rotate_left(1);
        let mut Do = BCi ^ BCu.rotate_left(1);
        let mut Du = BCo ^ BCa.rotate_left(1);
    
        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = Age.rotate_left(44);
        Aki ^= Di;
        BCi = Aki.rotate_left(43);
        Amo ^= Do;
        BCo = Amo.rotate_left(21);
        Asu ^= Du;
        BCu = Asu.rotate_left(14);
        let mut Eba = BCa ^ (!BCe & BCi);
        Eba ^= rc[0];
        let mut Ebe = BCe ^ (!BCi & BCo);
        let mut Ebi = BCi ^ (!BCo & BCu);
        let mut Ebo = BCo ^ (!BCu & BCa);
        let mut Ebu = BCu ^ (!BCa & BCe);

        Abo ^= Do;
        BCa = Abo.rotate_left(28);
        Agu ^= Du;
        BCe = Agu.rotate_left(20);
        Aka ^= Da;
        BCi = Aka.rotate_left(3);
        Ame ^= De;
        BCo = Ame.rotate_left(45);
        Asi ^= Di;
        BCu = Asi.rotate_left(61);
        let mut Ega = BCa ^ (!BCe & BCi);
        let mut Ege = BCe ^ (!BCi & BCo);
        let mut Egi = BCi ^ (!BCo & BCu);
        let mut Ego = BCo ^ (!BCu & BCa);
        let mut Egu = BCu ^ (!BCa & BCe);

        Abe ^= De;
        BCa = Abe.rotate_left(1);
        Agi ^= Di;
        BCe = Agi.rotate_left(6);
        Ako ^= Do;
        BCi = Ako.rotate_left(25);
        Amu ^= Du;
        BCo = Amu.rotate_left(8);
        Asa ^= Da;
        BCu = Asa.rotate_left(18);
        let mut Eka = BCa ^ (!BCe & BCi);
        let mut Eke = BCe ^ (!BCi & BCo);
        let mut Eki = BCi ^ (!BCo & BCu);
        let mut Eko = BCo ^ (!BCu & BCa);
        let mut Eku = BCu ^ (!BCa & BCe);

        Abu ^= Du;
        BCa = Abu.rotate_left(27);
        Aga ^= Da;
        BCe = Aga.rotate_left(36);
        Ake ^= De;
        BCi = Ake.rotate_left(10);
        Ami ^= Di;
        BCo = Ami.rotate_left(15);
        Aso ^= Do;
        BCu = Aso.rotate_left(56);
        let mut Ema = BCa ^ (!BCe & BCi);
        let mut Eme = BCe ^ (!BCi & BCo);
        let mut Emi = BCi ^ (!BCo & BCu);
        let mut Emo = BCo ^ (!BCu & BCa);
        let mut Emu = BCu ^ (!BCa & BCe);

        Abi ^= Di;
        BCa = Abi.rotate_left(62);
        Ago ^= Do;
        BCe = Ago.rotate_left(55);
        Aku ^= Du;
        BCi = Aku.rotate_left(39);
        Ama ^= Da;
        BCo = Ama.rotate_left(41);
        Ase ^= De;
        BCu = Ase.rotate_left(2);
        let mut Esa = BCa ^ (!BCe & BCi);
        let mut Ese = BCe ^ (!BCi & BCo);
        let mut Esi = BCi ^ (!BCo & BCu);
        let mut Eso = BCo ^ (!BCu & BCa);
        let mut Esu = BCu ^ (!BCa & BCe);

        // prepareTheta
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu ^ BCe.rotate_left(1);
        De = BCa ^ BCi.rotate_left(1);
        Di = BCe ^ BCo.rotate_left(1);
        Do = BCi ^ BCu.rotate_left(1);
        Du = BCo ^ BCa.rotate_left(1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = Ege.rotate_left(44);
        Eki ^= Di;
        BCi = Eki.rotate_left(43);
        Emo ^= Do;
        BCo = Emo.rotate_left(21);
        Esu ^= Du;
        BCu = Esu.rotate_left(14);
        Aba = BCa ^ (!BCe & BCi);
        Aba ^= rc[1];
        Abe = BCe ^ (!BCi & BCo);
        Abi = BCi ^ (!BCo & BCu);
        Abo = BCo ^ (!BCu & BCa);
        Abu = BCu ^ (!BCa & BCe);

        Ebo ^= Do;
        BCa = Ebo.rotate_left(28);
        Egu ^= Du;
        BCe = Egu.rotate_left(20);
        Eka ^= Da;
        BCi = Eka.rotate_left(3);
        Eme ^= De;
        BCo = Eme.rotate_left(45);
        Esi ^= Di;
        BCu = Esi.rotate_left(61);
        Aga = BCa ^ (!BCe & BCi);
        Age = BCe ^ (!BCi & BCo);
        Agi = BCi ^ (!BCo & BCu);
        Ago = BCo ^ (!BCu & BCa);
        Agu = BCu ^ (!BCa & BCe);

        Ebe ^= De;
        BCa = Ebe.rotate_left(1);
        Egi ^= Di;
        BCe = Egi.rotate_left(6);
        Eko ^= Do;
        BCi = Eko.rotate_left(25);
        Emu ^= Du;
        BCo = Emu.rotate_left(8);
        Esa ^= Da;
        BCu = Esa.rotate_left(18);
        Aka = BCa ^ (!BCe & BCi);
        Ake = BCe ^ (!BCi & BCo);
        Aki = BCi ^ (!BCo & BCu);
        Ako = BCo ^ (!BCu & BCa);
        Aku = BCu ^ (!BCa & BCe);

        Ebu ^= Du;
        BCa = Ebu.rotate_left(27);
        Ega ^= Da;
        BCe = Ega.rotate_left(36);
        Eke ^= De;
        BCi = Eke.rotate_left(10);
        Emi ^= Di;
        BCo = Emi.rotate_left(15);
        Eso ^= Do;
        BCu = Eso.rotate_left(56);
        Ama = BCa ^ (!BCe & BCi);
        Ame = BCe ^ (!BCi & BCo);
        Ami = BCi ^ (!BCo & BCu);
        Amo = BCo ^ (!BCu & BCa);
        Amu = BCu ^ (!BCa & BCe);

        Ebi ^= Di;
        BCa = Ebi.rotate_left(62);
        Ego ^= Do;
        BCe = Ego.rotate_left(55);
        Eku ^= Du;
        BCi = Eku.rotate_left(39);
        Ema ^= Da;
        BCo = Ema.rotate_left(41);
        Ese ^= De;
        BCu = Ese.rotate_left(2);
        Asa = BCa ^ (!BCe & BCi);
        Ase = BCe ^ (!BCi & BCo);
        Asi = BCi ^ (!BCo & BCu);
        Aso = BCo ^ (!BCu & BCa);
        Asu = BCu ^ (!BCa & BCe);
    }

    // copyToState(state, A)
    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

impl<const RATE: usize> KeccakCore<RATE> {
    fn init() -> Self {
        Self {
            state: [0u64; KECCAK_BLOCK_WORD_LEN],
            buf: [0u8; KECCAK_BLOCK_BYTE_LEN],
            pos: 0,
        }
    }

    fn absorb(&mut self, input: &[u8]) {
        let n = RATE - self.pos;
    
        if input.len() < n {
            // continue to fill the incomplete block
            self.buf[self.pos..self.pos + input.len()].copy_from_slice(input);
            self.pos += input.len()
        }
        else {
            // complete current block
            self.buf[self.pos..RATE].copy_from_slice(&input[..n]);
            for (src, dst) in self.buf[..RATE].chunks_exact(8).zip(self.state.iter_mut()) {
                *dst ^= u64::from_le_bytes(src.try_into().unwrap());
            }
            keccak_p(&mut self.state);

            // full blocks (xor directly in state)
            let iter_blocks = input[n..].chunks_exact(RATE);
            let rem_block = iter_blocks.remainder();
            for block in iter_blocks {
                for (src, dst) in block.chunks_exact(8).zip(self.state.iter_mut()) {
                    *dst ^= u64::from_le_bytes(src.try_into().unwrap());
                }
                keccak_p(&mut self.state);
            }

            // last incomplete block (copy in buf)
            self.pos = rem_block.len();
            self.buf[..self.pos].copy_from_slice(rem_block);
        }
    }

    fn finalize(&mut self, pad: u8) {
        // pad block
        self.buf[self.pos..].fill(0);
        self.buf[self.pos] = pad;
        self.buf[RATE - 1] |= 0x80;
        for (src, dst) in self.buf.chunks_exact(8).zip(self.state.iter_mut()) {
            *dst ^= u64::from_le_bytes(src.try_into().unwrap());
        }
    }

    fn absorb_once(&mut self, inputs: &[&[u8]], pad: u8) {
        let mut block = [0u8; RATE];
        let mut current = 0;
        for &input in inputs {
            // complete current block
            let remaining = RATE - current;
            if input.len() >= remaining {
                block[current..RATE].copy_from_slice(&input[..remaining]);
                for (src, dst) in block.chunks_exact(8).zip(self.state.iter_mut()) {
                    *dst ^= u64::from_le_bytes(src.try_into().unwrap());
                }
                keccak_p(&mut self.state);
            }
            else {
                block[current..current + input.len()].copy_from_slice(input);
                current += input.len();
                continue;
            }

            // full blocks
            let iter_blocks = input[remaining..].chunks_exact(RATE);
            let rem_block = iter_blocks.remainder();
            for block in iter_blocks {
                for (src, dst) in block.chunks_exact(8).zip(self.state.iter_mut()) {
                    *dst ^= u64::from_le_bytes(src.try_into().unwrap());
                }
                keccak_p(&mut self.state);
            }

            // incomplete block
            current = rem_block.len();
            block[..current].copy_from_slice(rem_block);
        }

        // pad last block
        block[current..].fill(0);
        block[current] = pad;
        block[RATE - 1] |= 0x80;
        for (src, dst) in block.chunks_exact(8).zip(self.state.iter_mut()) {
            *dst ^= u64::from_le_bytes(src.try_into().unwrap());
        }
    }

    fn squeeze_block(&mut self) {
        keccak_p(&mut self.state);
        for (chunk, w) in self.buf.chunks_exact_mut(8).zip(self.state) {
            chunk.copy_from_slice(&u64::to_le_bytes(w));
        }
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        let remaining_bytes = RATE - self.pos;
        let l = out.len();

        if l >= remaining_bytes {
            // use all remaining bytes of current state
            out[..remaining_bytes].copy_from_slice(&self.buf[self.pos..RATE]);
            self.pos = 0;
        }
        else {
            // use a part of the remaining bytes of current state
            out.copy_from_slice(&self.buf[self.pos..self.pos + l]);
            self.pos += l;
            return;
        }

        // full blocks
        for block in out[remaining_bytes..].chunks_exact_mut(RATE) {
            self.squeeze_block();
            block[..RATE].copy_from_slice(&self.buf[..RATE]);
        }

        // last bytes
        let rem_block = out[remaining_bytes..]
            .chunks_exact_mut(RATE)
            .into_remainder();
        self.squeeze_block();
        if !rem_block.is_empty() {
            rem_block.copy_from_slice(&self.buf[..rem_block.len()]);
            self.pos = rem_block.len();
        }
    }
}

impl<const RATE: usize> Zeroize for KeccakCore<RATE> {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Lines};
    use super::{
        Sha3_256,
        Sha3_512,
        Shake256,
        shake_hash_into,
        SHAKE128_RATE
    };

    // using byte-oriented test vectors from:
    // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing

    fn load_value(lines: &mut Lines<BufReader<File>>, prefix: &str) -> Option<Vec<u8>> {
        for line in lines.by_ref() {
            let Ok(line) = line else {
                return None
            };
            if !line.starts_with(prefix) {
                continue;
            }
            let (_, val_str) = line.split_at(prefix.len());
            return hex::decode(val_str.trim()).ok()
        }
        None
    }

    // message length is in bits
    fn load_len(lines: &mut Lines<BufReader<File>>) -> Option<usize> {
        for line in lines.by_ref() {
            let Ok(line) = line else { return None };
            if line.starts_with("Len = ") {
                let (_, val_str) = line.split_at(6);
                return val_str.parse::<usize>().ok();
            }
            else if line.starts_with("Outputlen = ") {
                let (_, val_str) = line.split_at(12);
                return val_str.parse::<usize>().ok()
            }
        }
        None
    }

    fn test_sha3_256(fname: &str, expected_count: usize) {
        let file = File::open(fname).unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(len) = load_len(&mut lines) {
            dbg!(count);
            let Some(message) = load_value(&mut lines, "Msg = ") else { break };
            let Some(expected) = load_value(&mut lines, "MD = ") else { break };
            let hash = match len {
                0 => {
                    assert_eq!(message, [0]);
                    Sha3_256::hash(&[b""])
                }
                _ => {
                    assert_eq!(message.len(), len / 8);
                    Sha3_256::hash(&[&message])
                }
            };
            assert_eq!(hash.as_ref(), expected);

            count += 1;
        }
        assert_eq!(count, expected_count);
    }

    fn test_sha3_512(fname: &str, expected_count: usize) {
        let file = File::open(fname).unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(len) = load_len(&mut lines) {
            dbg!(count);
            let Some(message) = load_value(&mut lines, "Msg = ") else { break };
            let Some(expected) = load_value(&mut lines, "MD = ") else { break };
            let hash = match len {
                0 => {
                    assert_eq!(message, [0]);
                    Sha3_512::hash(&[b""])
                }
                _ => {
                    assert_eq!(message.len(), len / 8);
                    Sha3_512::hash(&[&message])
                }
            };
            assert_eq!(hash.as_ref(), expected);

            if len > 0 { 
                assert_eq!(message.len(), len / 8);
                let mid = message.len() / 2;
                let (part1, part2) = unsafe { message.split_at_unchecked(mid) };
                let mut sha = Sha3_512::init();
                sha.update(part1);
                sha.update(part2);
                let hash = sha.finalize();
                assert_eq!(hash.as_ref(), expected);    
            }
            count += 1;
        }
        assert_eq!(count, expected_count);
    }

    fn test_shake_128(fname: &str, expected_count: usize) {
        let file = File::open(fname).unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;
        let mut buf = [0u8; 16];

        while let Some(len) = load_len(&mut lines) {
            let Some(message) = load_value(&mut lines, "Msg = ") else { break };
            let Some(expected) = load_value(&mut lines, "Output = ") else { break };
            match len {
                0 => {
                    assert_eq!(message, [0]);
                    shake_hash_into::<SHAKE128_RATE>(&[b""], &mut buf);

                },
                _ => {
                    assert_eq!(message.len(), len / 8);
                    shake_hash_into::<SHAKE128_RATE>(&[&message], &mut buf);
                }
            };
            assert_eq!(buf.as_ref(), expected);
            count += 1;
        }

        assert_eq!(count, expected_count);
    }

    fn test_shake_256(fname: &str, expected_count: usize) {
        let file = File::open(fname).unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;
        let mut buf = [0u8; 32];

        while let Some(len) = load_len(&mut lines) {
            let Some(message) = load_value(&mut lines, "Msg = ") else { break };
            let Some(expected) = load_value(&mut lines, "Output = ") else { break };
            match len {
                0 => {
                    assert_eq!(message, [0]);
                    Shake256::hash_into(&[b""], &mut buf);
                },
                _ => {
                    assert_eq!(message.len(), len / 8);
                    Shake256::hash_into(&[&message], &mut buf);
                }
            };
            assert_eq!(buf.as_ref(), expected);
            count += 1;
        }

        assert_eq!(count, expected_count);
    }

    #[test]
    fn test_sha3_256_short() {
        test_sha3_256("tests/SHA3_256ShortMsg.rsp", 137);
    }

    #[test]
    fn test_sha3_256_long() {
        test_sha3_256("tests/SHA3_256LongMsg.rsp", 100);
    }

    #[test]
    fn test_sha3_512_short() {
        test_sha3_512("tests/SHA3_512ShortMsg.rsp", 73);
    }

    #[test]
    fn test_sha3_512_long() {
        test_sha3_512("tests/SHA3_512LongMsg.rsp", 100);
    }

    #[test]
    fn test_shake128_short() {
        test_shake_128("tests/SHAKE128ShortMsg.rsp", 337);
    }

    #[test]
    fn test_shake128_long() {
        test_shake_128("tests/SHAKE128LongMsg.rsp", 100);
    }

    #[test]
    fn test_shake256_short() {
        test_shake_256("tests/SHAKE256ShortMsg.rsp", 273);
    }

    #[test]
    fn test_shake256_long() {
        test_shake_256("tests/SHAKE256LongMsg.rsp", 100);
    }

    #[test]
    fn test_shake_128_variable() {
        let file = File::open("tests/SHAKE128VariableOut.rsp").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(len) = load_len(&mut lines) {
            let Some(message) = load_value(&mut lines, "Msg = ") else { break };
            let Some(expected) = load_value(&mut lines, "Output = ") else { break };
            assert_eq!(len / 8, expected.len());
            let mut buf = vec![0u8; expected.len()];
            shake_hash_into::<SHAKE128_RATE>(&[&message], &mut buf);
            assert_eq!(buf.as_ref(), expected);
            count += 1;
        }

        assert_eq!(count, 1126);
    }

    #[test]
    fn test_shake_256_variable() {
        let file = File::open("tests/SHAKE256VariableOut.rsp").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(len) = load_len(&mut lines) {
            let Some(message) = load_value(&mut lines, "Msg = ") else { break };
            let Some(expected) = load_value(&mut lines, "Output = ") else { break };
            assert_eq!(len / 8, expected.len());
            let mut buf = vec![0u8; expected.len()];
            Shake256::hash_into(&[&message], &mut buf);
            assert_eq!(buf.as_ref(), expected);
            count += 1;
        }

        assert_eq!(count, 1246);
    }
}
