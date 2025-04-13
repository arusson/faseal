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

mod chacha20;
mod poly1305;

use zeroize::Zeroize;
use subtle::ConstantTimeEq;

use chacha20::ChaCha20;
use poly1305::Poly1305;

// invalid tag is the only possible error
#[derive(Debug)]
pub struct Error;

type Result<T> = core::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AEAD: decryption failure (invalid tag).")
    }
}

pub const KEY_LENGTH: usize = ChaCha20::KEY_LENGTH;
pub const NONCE_LENGTH: usize = ChaCha20::NONCE_LENGTH;
pub const TAG_LENGTH: usize = 16;

fn poly1305_keygen(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    otk: &mut [u8; Poly1305::KEY_LENGTH]
) {
    let mut chacha = ChaCha20::new(key, nonce, 0);
    chacha.gen_keystream_block();
    otk.copy_from_slice(&chacha.keystream()[..Poly1305::KEY_LENGTH]);
}

fn chacha20poly1305_auth(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    aad: &[u8], ciphertext: &[u8]
) -> [u8; TAG_LENGTH] {
    // generation of authentication key
    let mut otk = [0u8; Poly1305::KEY_LENGTH];
    poly1305_keygen(key, nonce, &mut otk);
    let mut poly = Poly1305::new(&otk);
    otk.zeroize();
   
    // authentication of additional data
    poly.update_padded(aad);
   
    // authentication of ciphertext
    poly.update_padded(ciphertext);
   
    // authentication of lengths
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&aad.len().to_le_bytes());
    lengths[8..].copy_from_slice(&ciphertext.len().to_le_bytes());
    poly.update(&lengths);

    poly.digest()
}

fn chacha20poly1305_encrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    aad: &[u8],
    plaintext: &[u8]
) -> (Vec<u8>, [u8; TAG_LENGTH]) {
    let ciphertext = ChaCha20::new(key, nonce, 1).encrypt(plaintext);
    let tag = chacha20poly1305_auth(key, nonce, aad, &ciphertext);
    (ciphertext, tag)
}

fn chacha20poly1305_encrypt_in_place(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    aad: &[u8],
    data: &mut [u8]
) -> [u8; TAG_LENGTH] {
    ChaCha20::new(key, nonce, 1).encrypt_in_place(data);
    chacha20poly1305_auth(key, nonce, aad, data)
}

fn chacha20poly1305_decrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LENGTH]
) -> Result<Vec<u8>> {
    let calc_tag = chacha20poly1305_auth(key, nonce, aad, ciphertext);

    // decryption only if tag is valid
    match tag.ct_eq(&calc_tag).into() {
        true => Ok(ChaCha20::new(key, nonce, 1).encrypt(ciphertext)),
        false => Err(Error),
    }
}

fn chacha20poly1305_decrypt_in_place(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG_LENGTH]
) -> Result<()> {
    let calc_tag = chacha20poly1305_auth(key, nonce, aad, data);

    // decryption only if tag is valid
    match tag.ct_eq(&calc_tag).into() {
        true => {
            ChaCha20::new(key, nonce, 1).encrypt_in_place(data);
            Ok(())
        },
        false => Err(Error),
    }
}

pub struct ChaCha20Poly1305 {
    key: [u8; KEY_LENGTH],
    nonce: [u8; NONCE_LENGTH]
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH]) -> Self {
        Self {
            key: *key,
            nonce: *nonce,
        }
    }

    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8] ) -> (Vec<u8>, [u8; TAG_LENGTH]) {
        chacha20poly1305_encrypt(&self.key, &self.nonce, aad, plaintext)
    }

    pub fn encrypt_in_place(&self, aad: &[u8], data: &mut [u8]) -> [u8; TAG_LENGTH] {
        chacha20poly1305_encrypt_in_place(&self.key, &self.nonce, aad, data)
    }

    pub fn decrypt(
        &self,
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LENGTH]
    ) -> Result<Vec<u8>> {
        chacha20poly1305_decrypt(&self.key, &self.nonce, aad, ciphertext, tag)
    }

    pub fn decrypt_in_place(
        &self,
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_LENGTH]
    ) -> Result<()> {
        chacha20poly1305_decrypt_in_place(&self.key, &self.nonce, aad, data, tag)
    }

    pub fn verify_tag(
        &self,
        aad: &[u8],
        data: &[u8],
        tag: &[u8; TAG_LENGTH]
    ) -> Result<()> {
        let calc_tag = chacha20poly1305_auth(&self.key, &self.nonce, aad, data);

        match tag.ct_eq(&calc_tag).into() {
            true => Ok(()),
            false => Err(Error),
        }
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChaCha20Poly1305,
        poly1305_keygen,
    };

    #[test]
    fn test_poly1305_keygen() {
        // source: https://datatracker.ietf.org/doc/html/rfc7539#section-2.6.2
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
        ];

        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07
        ];

        let expected_key: [u8; 32] = [
            0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc,
            0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2, 0x94, 0x71,
            0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5,
            0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46
        ];

        let mut poly1305key = [0u8; 32];
        poly1305_keygen(&key, &nonce, &mut poly1305key);
        assert_eq!(poly1305key, expected_key);
    }

    #[test]
    fn test_chacha20poly1305() {
        // source: https://datatracker.ietf.org/doc/html/rfc7539#section-2.8.2
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7
        ];

        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
        ];

        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00,
            0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
            0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
        ];

        let expected_ct = vec![
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
            0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
            0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
            0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
            0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
            0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
            0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
            0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
            0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
            0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
            0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
            0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
            0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16
        ];

        let cipher = ChaCha20Poly1305::new(&key, &nonce);

        let (ciphertext, tag) = cipher.encrypt(&aad, plaintext);
        assert_eq!(expected_ct, ciphertext);
        assert_eq!(expected_tag, tag);

        // in place
        let mut data = *plaintext;

        let tag = cipher.encrypt_in_place(&aad, &mut data);
        assert_eq!(expected_ct, data);
        assert_eq!(expected_tag, tag);
    }
}
