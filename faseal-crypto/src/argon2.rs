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

// adapted from https://github.com/P-H-C/phc-winner-argon2/

use std::ops::{
    BitXor, BitXorAssign
};
use secrecy::{
    ExposeSecret,
    SecretString
};

use crate::hashes::blake2::{
    Blake2b256,
    Blake2b512
};

// ----- Argon2 errors -----

#[derive(Debug)]
pub enum Error {
    InvalidTagLength,
    PasswordTooLong,
    SecretTooLong,
    SaltTooShort,
    SaltTooLong,
    AdditionalDataTooLong,
    MemoryCostTooSmall,
    MemoryCostTooLarge,
    TimeCostTooSmall,
    TimeCostTooLarge,
    ParallelCostTooSmall,
    ParallelCostTooLarge,
    WrongType,
}

type Result<T> = core::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTagLength => write!(f, "Argon2: output length invalid."),
            Self::PasswordTooLong => write!(f, "Argon2: password too long."),
            Self::SecretTooLong => write!(f, "Argon2: secret too long."),
            Self::SaltTooShort => write!(f, "Argon2: salt too short."),
            Self::SaltTooLong => write!(f, "Argon2: salt too long."),
            Self::AdditionalDataTooLong => write!(f, "Argon2: additional data too long."),
            Self::MemoryCostTooSmall => write!(f, "Argon2: memory cost too small."),
            Self::MemoryCostTooLarge => write!(f, "Argon2: memory cost too large."),
            Self::TimeCostTooSmall => write!(f, "Argon2: time cost too small."),
            Self::TimeCostTooLarge => write!(f, "Argon2: time cost too large."),
            Self::ParallelCostTooSmall => write!(f, "Argon2: parallel cost too small."),
            Self::ParallelCostTooLarge => write!(f, "Argon2: parallel cost too large."),
            Self::WrongType => write!(f, "Argon2: wrong type parameter."),
        }
    }
}

// ----- Argon 2 type -----

#[derive(Clone, Copy)]
#[derive(PartialEq)]
pub enum Argon2Type {
    Argon2d  = 0,
    Argon2i  = 1,
    Argon2id = 2
}

impl TryFrom<u8> for Argon2Type {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Argon2Type::Argon2d),
            1 => Ok(Argon2Type::Argon2i),
            2 => Ok(Argon2Type::Argon2id),
            _ => Err(Error::WrongType)
        }
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            cost_m: Self::DEFAULT_COST_M,
            cost_p: Self::DEFAULT_COST_P,
            cost_t: Self::DEFAULT_COST_T,
            tag_length: Self::DEFAULT_TAG_LENGTH,
            r#type: Argon2Type::Argon2id,
        }
    }
}

// ----- Argon2 parameters -----

pub struct Argon2Params {
    cost_m: usize,
    cost_p: usize,
    cost_t: usize,
    tag_length: usize,
    r#type: Argon2Type,
}

impl Argon2Params {
    pub const DEFAULT_COST_M: usize = 16 * 1024; // 16 MiB
    pub const DEFAULT_COST_P: usize = 1;
    pub const DEFAULT_COST_T: usize = 3;
    pub const DEFAULT_TAG_LENGTH: usize = 32;

    pub fn new(
        cost_m: usize,
        cost_p: usize,
        cost_t: usize,
    ) -> Self {
        Self {
            cost_m,
            cost_p,
            cost_t,
            ..Default::default()
        }
    }

    fn validate(&self) -> Result<()> {
        // This implementation only supports 32 and 64 bytes outputs.
        if self.tag_length != 32 && self.tag_length != 64 {
            Err(Error::InvalidTagLength)
        }
        else if self.cost_m < Argon2::MIN_MEMORY || self.cost_m < 8 * self.cost_p {
            Err(Error::MemoryCostTooSmall)
        }
        else if self.cost_m > Argon2::MAX_MEMORY {
            Err(Error::MemoryCostTooLarge)
        }
        else if self.cost_t < Argon2::MIN_TIME {
            Err(Error::TimeCostTooSmall)
        }
        else if self.cost_t > Argon2::MAX_TIME {
            Err(Error::TimeCostTooLarge)
        }
        else if self.cost_p < Argon2::MIN_LANES {
            Err(Error::ParallelCostTooSmall)
        }
        else if self.cost_p > Argon2::MAX_LANES {
            Err(Error::ParallelCostTooLarge)
        }
        else {
            Ok(())
        }
    }

    pub fn cost_m(&self) -> u32 {
        self.cost_m as u32
    }

    pub fn cost_p(&self) -> u32 {
        self.cost_p as u32
    }

    pub fn cost_t(&self) -> u32 {
        self.cost_t as u32
    }

    pub fn tag_length(&self) -> u64 {
        self.tag_length as u64
    }

    pub fn r#type(&self) -> u32 {
        self.r#type as u32
    }
}

impl std::fmt::Display for Argon2Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Password derivation: {} (memory: {}, parallel: {}, passes: {})",
            match self.r#type {
                Argon2Type::Argon2d => "Argon2d",
                Argon2Type::Argon2i => "Argon2i",
                Argon2Type::Argon2id => "Argon2id",
            },
            self.cost_m,
            self.cost_p,
            self.cost_t        
        )
    }
}

// ----- Argon2 -----

pub struct Argon2<'a> {
    params: &'a Argon2Params,
    memory_length: usize,
    segment_length: usize,
    lane_length: usize,
}

impl<'a> Argon2<'a> {
    // Minimum and maximum number of lanes (degree of parallelism)
    pub const MIN_LANES: usize = 1;
    pub const MAX_LANES: usize = 0xFF_FFFF;

    // Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes)
    pub const MIN_MEMORY: usize = 8; // 2 blocks per slice
    pub const MAX_MEMORY: usize = 0xFFFF_FFFF;

    // Minimum and maximum number of passes
    pub const MIN_TIME: usize = 1;
    pub const MAX_TIME: usize = 0xFFFF_FFFF;

    // Maximum password length in bytes
    const MAX_PWD_LENGTH: usize = 0xFFFF_FFFF;

    // Maximum associated data length in bytes
    const MAX_AD_LENGTH: usize = 0xFFFF_FFFF;

    // Minimum and maximum salt length in bytes
    const MIN_SALT_LENGTH: usize = 8;
    const MAX_SALT_LENGTH: usize = 0xFFFF_FFFF;

    // Maximum key length in bytes
    const MAX_SECRET: usize = 0xFFFF_FFFF;

    pub fn hash_into(
        password: &SecretString,
        salt: &[u8],
        secret: &[u8],
        additional_data: &[u8],
        params: &'a Argon2Params,
        out: &mut [u8]
    ) -> Result<()> {
        params.validate()?;
        let segment_length = params.cost_m / (4 * params.cost_p);
        let lane_length = segment_length * 4;
        let memory_length = lane_length * params.cost_p;
        let argon2 = Self {
            params,
            lane_length,
            memory_length,
            segment_length,
        };

        if out.len() != argon2.params.tag_length {
            return Err(Error::InvalidTagLength);
        }
        validate_inputs(password, salt, secret, additional_data)?;

        // 2. Allocate the memory as m' 1024-byte blocks, where m' is derived as:
        //
        //    m' = 4 * p * floor (m / 4p)
        let mut memory = vec![Block::ZERO; argon2.memory_length];

        // 1. Establish H_0...
        // 3. Compute B[i][0]...
        // 4. Compute B[i][1]...
        argon2.initialize(password, salt, secret, additional_data, &mut memory);

        // 5. Compute B[i][j]...
        // 6. If the number of passes t...
        argon2.fill_memory_block(&mut memory);

        // 7. After t steps have been iterated
        argon2.finalize_into(&mut memory, out);
        Ok(())
    }

    fn initialize(
        &self,
        password: &SecretString,
        salt: &[u8],
        secret: &[u8],
        additional_data: &[u8],
        memory: &mut [Block]
    ) {
        // 1. Establish H_0 as the 64-byte value as shown below.
        //    If K, X, or S has zero length, it is just absent, but its length ﬁeld remains.
        //
        //    H_0 = H^(64)(LE32(p) || LE32(T) || LE32(m) || LE32(t) ||
        //    LE32(v) || LE32(y) || LE32(length(P)) || P ||
        //    LE32(length(S)) || S || LE32(length(K)) || K ||
        //    LE32(length(X)) || X)
        let mut digest = Blake2b512::init();
        digest.update(&(self.params.cost_p as u32).to_le_bytes());
        digest.update(&(self.params.tag_length as u32).to_le_bytes());
        digest.update(&(self.params.cost_m as u32).to_le_bytes());
        digest.update(&(self.params.cost_t as u32).to_le_bytes());
        digest.update(&[0x13u8, 0, 0, 0]);
        digest.update(&(self.params.r#type as u32).to_le_bytes());
        digest.update(&(password.expose_secret().len() as u32).to_le_bytes());
        digest.update(password.expose_secret().as_bytes());
        digest.update(&(salt.len() as u32).to_le_bytes());
        digest.update(salt);
        digest.update(&(secret.len() as u32).to_le_bytes());
        digest.update(secret);
        digest.update(&(additional_data.len() as u32).to_le_bytes());
        digest.update(additional_data);
        
        let mut blockhash = [0u8; 72];
        blockhash[..64].copy_from_slice(&digest.finalize());

        // 3. Compute B[i][0] for all i ranging from (and including) 0 to (not including) p.
        //
        //    B[i][0] = H'^(1024)(H_0 || LE32(0) || LE32(i))

        // 4. Compute B[i][1] for all i ranging from (and including) 0 to (not including) p.
        //
        //    B[i][1] = H'^(1024)(H_0 || LE32(1) || LE32(i))
        let mut output = [0u8; 1024];
        for (i, lane) in memory.chunks_exact_mut(self.lane_length).enumerate() {
            blockhash[68..].copy_from_slice(&(i as u32).to_le_bytes());
            for (j, block) in lane.iter_mut().take(2).enumerate() {
                blockhash[64] = j as u8;
                blake2b_long(&blockhash, &mut output);
                block.load(&output);
            }
        }
    }

    fn fill_memory_block(&self, memory: &mut [Block]) {        
        // 5. Compute B[i][j] for all i ranging from (and including) 0 to (not including) p
        //    and for all j ranging from (and including) 2 to (not including) q.
        //    The computation MUST proceed slicewise (Section 3.4): ﬁrst, blocks from slice 0
        //    are computed for all lanes (in an arbitrary order of lanes), then blocks from slice 1
        //    are computed, etc. The block indices l and z are determined for each i, j diﬀerently
        //    for Argon2d, Argon2i, and Argon2id.
        // 
        //    B[i][j] = G(B[i][j-1], B[l][z])

        // 6. If the number of passes t is larger than 1, we repeat step 5. We compute B[i][0] and
        //    B[i][j] for all i ranging from (and including) 0 to (not including) p and for all j
        //    ranging from (and including) 1 to (not including) q. However, blocks are computed
        //    diﬀerently as the old value is XORed with the new one:
        //
        //    B[i][0] = G(B[i][q-1], B[l][z]) XOR B[i][0];
        //    B[i][j] = G(B[i][j-1], B[l][z]) XOR B[i][j].

        for iteration in 0..self.params.cost_t {
            for slice in 0..4 {
                for lane in 0..self.params.cost_p {
                    let mut position = Position::new(iteration, lane, slice, 0);
                    self.fill_segment(memory, &mut position);
                }
            }
        }
    }

    fn finalize_into(&self, memory: &mut [Block], out: &mut [u8]) {
        // 7. After t steps have been iterated, the ﬁnal block C is computed
        //    as the XOR of the last column:
        //
        //    C = B[0][q-1] XOR B[1][q-1] XOR ... XOR B[p-1][q-1]
        let mut final_block = memory[self.lane_length - 1].clone();
        for block in memory.iter().skip(2*self.lane_length - 1).step_by(self.lane_length) {
            final_block ^= block;
        }

        // 8. The output tag is computed as H'^T(C).
        blake2b_long(&final_block.dump(), out);
    }

    fn fill_segment(&self, memory: &mut [Block], position: &mut Position) {
        let data_independent_processing = self.params.r#type == Argon2Type::Argon2i
            || (self.params.r#type == Argon2Type::Argon2id
                && position.iteration == 0 && position.slice < 2);

        let mut input_block = Block::ZERO;
        if data_independent_processing {
            input_block.0[0] = position.iteration as u64;
            input_block.0[1] = position.lane as u64;
            input_block.0[2] = position.slice as u64;
            input_block.0[3] = self.memory_length as u64;
            input_block.0[4] = self.params.cost_t as u64;
            input_block.0[5] = self.params.r#type as u64;
        }

        let mut starting_index = 0;
        let mut address_block = Block::ZERO;
        if position.iteration == 0 && position.slice == 0 {
            starting_index = 2;

            if data_independent_processing {
                address_block.next_addresses(&mut input_block);
            }
        }

        let mut curr_offset = position.lane * self.lane_length
            + position.slice * self.segment_length + starting_index;

        let mut prev_offset = if curr_offset.is_multiple_of(self.lane_length) {
            curr_offset + self.lane_length - 1
        }
        else {
            curr_offset - 1
        };

        for i in starting_index..self.segment_length {
            if curr_offset % self.lane_length == 1 {
                prev_offset = curr_offset - 1;
            }

            let pseudo_rand = if data_independent_processing {
                if i % 128 == 0 {
                    address_block.next_addresses(&mut input_block);
                }
                address_block.0[i % 128]
            }
            else {
                memory[prev_offset].0[0]
            };

            let ref_lane = if position.iteration == 0 && position.slice == 0 {
                position.lane
            }
            else {
                (pseudo_rand >> 32) as usize % self.params.cost_p
            };

            position.index = i;
            let ref_index = self.index_alpha(
                position,
                pseudo_rand & 0xFFFF_FFFF,
                ref_lane == position.lane
            );

            let ref_block = &memory[self.lane_length * ref_lane + ref_index];
            let result = Block::compress(&memory[prev_offset], ref_block);
            let cur_block = &mut memory[curr_offset];
            match position.iteration {
                0 => *cur_block = result,
                _ => *cur_block ^= &result,
            }

            curr_offset += 1;
            prev_offset += 1;
        }

    }

    fn index_alpha(&self, position: &Position, pseudo_rand: u64, same_lane: bool) -> usize {
        let reference_area_size = if position.iteration == 0 {
            if position.slice == 0 {
                position.index - 1
            }
            else if same_lane {
                position.slice * self.segment_length + position.index - 1
            }
            else if position.index == 0 {
                position.slice * self.segment_length - 1
            }
            else {
                position.slice * self.segment_length
            }
        }
        else if same_lane {
            self.lane_length - self.segment_length + position.index - 1
        }
        else if position.index == 0 {
            self.lane_length - self.segment_length - 1
        }
        else {
            self.lane_length - self.segment_length
        } as u64;

        let mut relative_position = pseudo_rand;
        relative_position = (relative_position * relative_position) >> 32;
        relative_position =
            reference_area_size - 1 - ((reference_area_size * relative_position) >> 32);

        let start_position = match position.iteration {
            0 => 0,
            _ => match position.slice {
                3 => 0,
                _ => (position.slice + 1) * self.segment_length
            }
        };

        (start_position + relative_position as usize) % self.lane_length
    }
}

// ----- Argon2 blocks and other things -----

#[derive(Clone)]
struct Block([u64; 128]);

impl BitXorAssign<&Block> for Block {
    fn bitxor_assign(&mut self, rhs: &Self) {
        for (dst, src) in self.0.iter_mut().zip(rhs.0) {
            *dst ^= src;
        }
    }
}

impl BitXor<&Block> for &Block {
    type Output = Block;
    fn bitxor(self, rhs: &Block) -> Self::Output {
        let mut block = self.clone();
        block ^= rhs;
        block
    }
}

impl Block {
    const ZERO: Block = Block([0; 128]);

    fn load(&mut self, input: &[u8; 1024]) {
        for (dst, src) in self.0.iter_mut().zip(input.chunks_exact(8)) {
            *dst = u64::from_le_bytes(src.try_into().unwrap());
        }
    }

    fn dump(&self) -> [u8; 1024] {
        let mut out = [0u8; 1024];
        for (dst, src) in out.chunks_exact_mut(8).zip(self.0.iter()) {
            dst.copy_from_slice(&src.to_le_bytes());
        }
        out
    }

    fn compress(in1: &Self, in2: &Self) -> Self {
        const TRUNC: u64 = 0xFFFF_FFFF;
        macro_rules! gb {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {
                let mut t = (($a & TRUNC) * ($b & TRUNC)).wrapping_mul(2);
                $a = $a.wrapping_add($b);
                $a = $a.wrapping_add(t);
                $d = ($d ^ $a).rotate_right(32);
        
                t = (($c & TRUNC) * ($d & TRUNC)).wrapping_mul(2);
                $c = $c.wrapping_add($d);
                $c = $c.wrapping_add(t);
                $b = ($b ^ $c).rotate_right(24);
        
                t = (($a & TRUNC) * ($b & TRUNC)).wrapping_mul(2);
                $a = $a.wrapping_add($b);
                $a = $a.wrapping_add(t);
                $d = ($d ^ $a).rotate_right(16);
        
                t = (($c & TRUNC) * ($d & TRUNC)).wrapping_mul(2);
                $c = $c.wrapping_add($d);
                $c = $c.wrapping_add(t);
                $b = ($b ^ $c).rotate_right(63);
            };
        }
        
        macro_rules! permutation {
            (
                $v0:expr,  $v1:expr,  $v2:expr,  $v3:expr, 
                $v4:expr,  $v5:expr,  $v6:expr,  $v7:expr, 
                $v8:expr,  $v9:expr,  $v10:expr, $v11:expr, 
                $v12:expr, $v13:expr, $v14:expr, $v15:expr
            ) => {
                gb!($v0, $v4, $v8,  $v12);
                gb!($v1, $v5, $v9,  $v13);
                gb!($v2, $v6, $v10, $v14);
                gb!($v3, $v7, $v11, $v15);
            
                gb!($v0, $v5, $v10, $v15);
                gb!($v1, $v6, $v11, $v12);
                gb!($v2, $v7, $v8,  $v13);
                gb!($v3, $v4, $v9,  $v14);
            };
        }
        
        let mut r = in1 ^ in2;
        let mut out = r.clone();

        for row in r.0.chunks_exact_mut(16) {
            permutation!(
                row[0],  row[1],  row[2],  row[3],
                row[4],  row[5],  row[6],  row[7],
                row[8],  row[9],  row[10], row[11],
                row[12], row[13], row[14], row[15]
            );
        }
   
        for i in (0..16).step_by(2) {
            permutation!(
                r.0[i], r.0[i + 1],
                r.0[i + 16], r.0[i + 17],
                r.0[i + 32], r.0[i + 33],
                r.0[i + 48], r.0[i + 49],
                r.0[i + 64], r.0[i + 65],
                r.0[i + 80], r.0[i + 81],
                r.0[i + 96], r.0[i + 97],
                r.0[i + 112], r.0[i + 113]
            );
        }

        out ^= &r;
        out
    }

    fn next_addresses(&mut self, input_block: &mut Block) {
        input_block.0[6] += 1;
        *self = Block::compress(&Block::ZERO, input_block);
        *self = Block::compress(&Block::ZERO, self);
    }
}

struct Position {
    iteration: usize,
    lane: usize,
    slice: usize,
    index: usize
}

impl Position {
    fn new(iteration: usize, lane: usize, slice: usize, index: usize) -> Self {
        Self {
            iteration,
            lane,
            slice,
            index
        }
    }
}

fn validate_inputs(
    password: &SecretString,
    salt: &[u8],
    secret: &[u8],
    additional_data: &[u8],
) -> Result<()> {
    if password.expose_secret().len() > Argon2::MAX_PWD_LENGTH {
        Err(Error::PasswordTooLong)
    }
    else if salt.len() < Argon2::MIN_SALT_LENGTH {
        Err(Error::SaltTooShort)
    }
    else if salt.len() > Argon2::MAX_SALT_LENGTH {
        Err(Error::SaltTooLong)
    }
    else if secret.len() > Argon2::MAX_SECRET {
        Err(Error::SecretTooLong)
    }
    else if additional_data.len() > Argon2::MAX_AD_LENGTH {
        Err(Error::AdditionalDataTooLong)
    }
    else {
        Ok(())
    }
}

fn blake2b_long(input: &[u8], output: &mut [u8]) {
    if output.len() == 32 {
        // Cannot panic, length is valid
        let mut blake = Blake2b256::init();
        blake.update(&(output.len() as u32).to_le_bytes());
        blake.update(input);
        // Cannot panic, sizes are the same
        output.copy_from_slice(&blake.finalize());
    }
    else {
        let r = output.len().div_ceil(32) - 2;

        // V_1 = H^(64)(LE32(T)||A)
        let mut blake = Blake2b512::init();
        blake.update(&(output.len() as u32).to_le_bytes());
        blake.update(input);
        let mut block = blake.finalize();
        output[..32].copy_from_slice(&block[..32]);

        // V_2 = H^(64)(V_1)
        // ...
        // V_r = H^(64)(V_{r-1})
        for chunk in output[32..32 * r].chunks_exact_mut(32) {
            block = Blake2b512::hash(&block);
            chunk.copy_from_slice(&block[..32]);
        }

        // V_{r+1} = H^(T-32*r)(V_{r})
        // Only expect 64 bytes, so Blake2b512 is used
        let last_block = Blake2b512::hash(&block);
        output[32 * r..].copy_from_slice(&last_block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2d() {
        // source: https://datatracker.ietf.org/doc/html/rfc9106#section-5.1
        let params = Argon2Params {
            cost_m: 32,
            cost_p: 4,
            cost_t: 3,
            tag_length: 32,
            r#type: Argon2Type::Argon2d
        };
        let password = SecretString::from(
            unsafe { String::from_utf8_unchecked(vec![0x01; 32]) }
        );

        let salt = [0x02; 16];
        let secret = [0x03; 8];
        let ad = [0x04; 12];
        let expected = hex_literal::hex!(
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
        );

        let mut hash = [0u8; 32];
        Argon2::hash_into(&password, &salt, &secret, &ad, &params, &mut hash).unwrap();
        assert_eq!(hash, expected);
        
        let params = Argon2Params {
            cost_m: 32,
            cost_p: 4,
            cost_t: 3,
            tag_length: 32,
            r#type: Argon2Type::Argon2i
        };
        let expected = hex_literal::hex!(
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"
        );

        let mut hash = [0u8; 32];
        Argon2::hash_into(&password, &salt, &secret, &ad, &params, &mut hash).unwrap();
        assert_eq!(hash, expected);

        let params = Argon2Params {
            cost_m: 32,
            cost_p: 4,
            cost_t: 3,
            tag_length: 32,
            r#type: Argon2Type::Argon2id
        };
        let expected = hex_literal::hex!(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );

        let mut hash = [0u8; 32];
        Argon2::hash_into(&password, &salt, &secret, &ad, &params, &mut hash).unwrap();
        assert_eq!(hash, expected);
    }
}
