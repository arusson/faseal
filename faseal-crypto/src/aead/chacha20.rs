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

pub(crate) struct ChaCha20 {
    initial_state: [u32; 16],
    keystream: [u8; Self::BLOCK_SIZE],
    counter: usize,
}

impl ChaCha20 {
    pub(crate) const NONCE_LENGTH: usize = 12;
    pub(crate) const KEY_LENGTH: usize = 32;
    pub(crate) const BLOCK_SIZE: usize = 64;

    pub(crate) fn new(
        key: &[u8; Self::KEY_LENGTH],
        nonce: &[u8; Self::NONCE_LENGTH],
        counter: usize
    ) -> Self {
        Self {
            initial_state: [
                0x61707865,
                0x3320646e,
                0x79622d32,
                0x6b206574,
                u32::from_le_bytes(key[0..4].try_into().unwrap()),
                u32::from_le_bytes(key[4..8].try_into().unwrap()),
                u32::from_le_bytes(key[8..12].try_into().unwrap()),
                u32::from_le_bytes(key[12..16].try_into().unwrap()),
                u32::from_le_bytes(key[16..20].try_into().unwrap()),
                u32::from_le_bytes(key[20..24].try_into().unwrap()),
                u32::from_le_bytes(key[24..28].try_into().unwrap()),
                u32::from_le_bytes(key[28..32].try_into().unwrap()),
                0,
                u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
                u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
                u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
            ],
            keystream: [0u8; Self::BLOCK_SIZE],
            counter,
        }
    }

    pub(crate) fn keystream(&self) -> &[u8; Self::BLOCK_SIZE] {
        &self.keystream
    }

    pub(crate) fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut ct = vec![0u8; plaintext.len()];
        for (pchunk, cchunk) in plaintext.chunks(Self::BLOCK_SIZE)
            .zip(ct.chunks_mut(Self::BLOCK_SIZE))
        {
            self.gen_keystream_block();
            xor(cchunk, &self.keystream, pchunk);
            self.counter += 1;
        }
        ct
    }

    pub(crate) fn encrypt_in_place(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_mut(Self::BLOCK_SIZE) {
            self.gen_keystream_block();
            xor_in_place(chunk, &self.keystream);
            self.counter += 1;
        }
    }

    pub(crate) fn gen_keystream_block(&mut self) {
        self.initial_state[12] = self.counter as u32;
        let mut state = self.initial_state;
    
        // rounds
        for _ in 0..10 {
            inner_block(&mut state);
        }
    
        // add initial state
        for (s, &is) in state.iter_mut().zip(self.initial_state.iter()) {
            *s = s.wrapping_add(is);
        }
    
        // output to buffer array
        for (chunk, val) in self.keystream.chunks_exact_mut(4).zip(state.iter()) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        state.zeroize();
    }
}

fn xor(res: &mut [u8], buf1: &[u8], buf2: &[u8]) {
    for (r, (&a, &b)) in res.iter_mut().zip(buf1.iter().zip(buf2.iter())) {
        *r = a ^ b;
    }
}

fn xor_in_place(out: &mut [u8], buf: &[u8]) {
    for (a, &b) in out.iter_mut().zip(buf.iter()) {
        *a ^= b;
    }
}

fn inner_block(state: &mut [u32; 16]) {
    macro_rules! quarter_round {
        ($i:expr, $j:expr, $k:expr, $l:expr) => {
            state[$i] = state[$i].wrapping_add(state[$j]);
            state[$l] ^= state[$i];
            state[$l] = state[$l].rotate_left(16);
        
            state[$k] = state[$k].wrapping_add(state[$l]);
            state[$j] ^= state[$k];
            state[$j] = state[$j].rotate_left(12);
        
            state[$i] = state[$i].wrapping_add(state[$j]);
            state[$l] ^= state[$i];
            state[$l] = state[$l].rotate_left(8);
        
            state[$k] = state[$k].wrapping_add(state[$l]);
            state[$j] ^= state[$k];
            state[$j] = state[$j].rotate_left(7);
        };
    }

    quarter_round!(0, 4, 8, 12);
    quarter_round!(1, 5, 9, 13);
    quarter_round!(2, 6, 10, 14);
    quarter_round!(3, 7, 11, 15);
    quarter_round!(0, 5, 10, 15);
    quarter_round!(1, 6, 11, 12);
    quarter_round!(2, 7, 8, 13);
    quarter_round!(3, 4, 9, 14);
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        self.initial_state.zeroize();
        self.keystream.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_chacha20() {
        // source: https://datatracker.ietf.org/doc/html/rfc7539#section-2.4.2
        let key: [u8; 32] = hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
    
        let nonce: [u8; 12] = hex!("000000000000004a00000000");

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct: [u8; 114] = hex!(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
            "5af90bbf74a35be6b40b8eedf2785e42874d"
        );

        let ciphertext = ChaCha20::new(&key, &nonce, 1).encrypt(plaintext);
        let decrypted = ChaCha20::new(&key, &nonce, 1).encrypt(&ciphertext);
        assert_eq!(decrypted, plaintext);
        assert_eq!(ciphertext, expected_ct);

        let mut ciphertext = *plaintext;
        ChaCha20::new(&key, &nonce, 1).encrypt_in_place(&mut ciphertext);
        let mut decrypted = ciphertext;
        ChaCha20::new(&key, &nonce, 1).encrypt_in_place(&mut decrypted);
        assert_eq!(&decrypted, plaintext);
        assert_eq!(ciphertext, expected_ct);
    }
}
