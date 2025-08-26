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

// adapted from https://github.com/PQClean/PQClean/tree/master/crypto_kem/ml-kem-768/clean

mod fq;
mod pke;
mod poly;
pub(crate) mod polyvec;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use pke::{
    k_pke_keygen,
    k_pke_encrypt,
    k_pke_decrypt,
    PKE_CT_LEN,
    PKE_PK_LEN,
    PKE_SK_LEN

};
use crate::hashes::sha3::{
    Sha3_256,
    Sha3_512,
    Shake256
};

const MLKEM_K: usize = 3;
const MLKEM_Q: i16 = 3329;
const MLKEM_Q32: i32 = 3329;

pub(crate) const OFFSET_EK: usize = PKE_SK_LEN;
pub(crate) const OFFSET_HASH_EK: usize = PKE_SK_LEN + PKE_PK_LEN;
pub(crate) const OFFSET_Z: usize = OFFSET_HASH_EK + 32;

pub(crate) struct MlKem768;

impl MlKem768 {
    pub(crate) const ENCAPSKEY_LEN: usize = PKE_PK_LEN;
    pub(crate) const DECAPSKEY_LEN: usize = PKE_SK_LEN + Self::ENCAPSKEY_LEN + 64;
    pub(crate) const CIPHERTEXT_LEN: usize = PKE_CT_LEN;
    pub(crate) const OFFSET_EK: usize = OFFSET_EK;

    // FIPS 203, algorithm 16
    pub(crate) fn keygen_derand(
        d: &[u8; 32],
        z: &[u8; 32],
        ek: &mut [u8; Self::ENCAPSKEY_LEN],
        dk: &mut [u8; Self::DECAPSKEY_LEN]
    ) {
        k_pke_keygen(d, ek, dk[..OFFSET_EK].as_mut().try_into().unwrap());
        dk[OFFSET_EK..OFFSET_HASH_EK].copy_from_slice(ek);
        Sha3_256::hash_into(
            &[ek],
            dk[OFFSET_HASH_EK..OFFSET_Z].as_mut().try_into().unwrap()
        );
        dk[OFFSET_Z..].copy_from_slice(z);
    }

    // FIPS 203, algorithm 17
    pub(crate) fn encaps_derand(
        ek: &[u8; Self::ENCAPSKEY_LEN],
        m: &[u8; 32],
        ss: &mut [u8; 32],
        ct: &mut [u8; MlKem768::CIPHERTEXT_LEN]
    ) {
        let h = Sha3_256::hash(&[ek]);
        let mut k_r = Sha3_512::hash(&[m, &h]);
        ss.copy_from_slice(&k_r[..32]);
        k_pke_encrypt(ek, m, k_r[32..].try_into().unwrap(), ct);
        k_r.zeroize();
    }

    // FIPS 203, algorithm 18
    pub(crate) fn decaps(
        dk: &[u8; Self::DECAPSKEY_LEN],
        ct: &[u8; Self::CIPHERTEXT_LEN],
        ss: &mut [u8; 32]
    ) {
        let dp_pke: &[u8; PKE_SK_LEN] = dk[..OFFSET_EK].try_into().unwrap();
        let ek_pke: &[u8; PKE_PK_LEN] = dk[OFFSET_EK..OFFSET_HASH_EK].try_into().unwrap();
        let h = &dk[OFFSET_HASH_EK..OFFSET_Z];
        let z = &dk[OFFSET_Z..];
        let mut m = [0u8; 32];
        k_pke_decrypt(ct, dp_pke, &mut m);
        let mut k_r = Sha3_512::hash(&[&m, h]);
        Shake256::hash_into(&[z, ct], ss);
        let mut ct_prime = [0u8; Self::CIPHERTEXT_LEN];
        k_pke_encrypt(ek_pke, &m, &k_r[32..].try_into().unwrap(), &mut ct_prime);
        m.zeroize();

        let mask = (-(ct_prime.ct_eq(ct).unwrap_u8() as i8)) as u8;
        for (a, &b) in ss.iter_mut().zip(k_r.iter()) {
            *a ^= mask & (*a ^ b);
        }
        k_r.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Lines};
    use rand::RngCore;
    use super::MlKem768;

    #[test]
    fn test_ml_kem_1() {
        // key generation
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        rand::rng().fill_bytes(&mut d);
        rand::rng().fill_bytes(&mut z);
        let mut dk = [0u8; MlKem768::DECAPSKEY_LEN];
        let mut ek = [0u8; MlKem768::ENCAPSKEY_LEN];
        MlKem768::keygen_derand(&d, &z, &mut ek, &mut dk);
    
        // encapsulation
        let mut ss1 = [0u8; 32];
        let mut ct = [0u8; MlKem768::CIPHERTEXT_LEN];
        let mut m = [0u8; 32];
        rand::rng().fill_bytes(&mut m);
        MlKem768::encaps_derand(&ek, &m, &mut ss1, &mut ct);

        // decapsulation
        let mut ss2 = [0u8; 32];
        MlKem768::decaps(&dk, &ct, &mut ss2);
        assert_eq!(ss1, ss2);
    }

    fn load_value(lines: &mut Lines<BufReader<File>>, prefix: &str) -> Option<Vec<u8>> {
        for line in lines.by_ref() {
            let Ok(line) = line else { return None };
            if !line.starts_with(prefix) {
                continue;
            }
            let (_, val_str) = line.split_at(prefix.len());
            return hex::decode(val_str.trim()).ok()
        }
        None
    }

    fn load_id(lines: &mut Lines<BufReader<File>>) -> Option<usize> {
        for line in lines.by_ref() {
            let Ok(line) = line else { return None };
            if !line.starts_with("tcId") {
                continue;
            }
            let (_, val_str) = line.split_at(6);
            return val_str.parse::<usize>().ok()
        }
        None
    }

    fn load_text(lines: &mut Lines<BufReader<File>>, prefix: &str) -> Option<String> {
        for line in lines.by_ref() {
            let Ok(line) = line else { return None };
            if !line.starts_with(prefix) {
                continue;
            }
            let (_, val_str) = line.split_at(prefix.len());
            return Some(val_str.to_string());
        }
        None
    }

    #[test]
    fn test_ml_kem_keygen_acvp() {
        // test vectors from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json

        let file = File::open("tests/ml_kem_768_keygen.txt").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(_id) = load_id(&mut lines) {
            dbg!(count);
            let Some(z) = load_value(&mut lines, "z:") else { break };
            let Some(d) = load_value(&mut lines, "d:") else { break };
            let Some(expected_ek) = load_value(&mut lines, "ek:") else { break };
            let Some(expected_dk) = load_value(&mut lines, "dk:") else { break };

            let mut ek = [0u8; MlKem768::ENCAPSKEY_LEN];
            let mut dk = [0u8; MlKem768::DECAPSKEY_LEN];
        
            MlKem768::keygen_derand(
                d.as_slice().try_into().unwrap(),
                z.as_slice().try_into().unwrap(),
                &mut ek,
                &mut dk
            );
        
            assert_eq!(ek, expected_ek.as_slice());
            assert_eq!(dk, expected_dk.as_slice());
            count += 1;
        }
        assert_eq!(count, 25);
    }
 
    #[test]
    fn test_ml_kem_encaps_acvp() {
        // test vectors from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json
 
        let file = File::open("tests/ml_kem_768_encaps.txt").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(_id) = load_id(&mut lines) {
            dbg!(count);
            let Some(ek) = load_value(&mut lines, "ek:") else { break };
            let Some(expected_c) = load_value(&mut lines, "c:") else { break };
            let Some(expected_k) = load_value(&mut lines, "k:") else { break };
            let Some(m) = load_value(&mut lines, "m:") else { break };

            let mut k = [0u8; 32];
            let mut c = [0u8; MlKem768::CIPHERTEXT_LEN];

            MlKem768::encaps_derand(
                ek.as_slice().try_into().unwrap(),
                m.as_slice().try_into().unwrap(),
                &mut k,
                &mut c
            );
        
            assert_eq!(k, expected_k.as_slice());
            assert_eq!(c, expected_c.as_slice());
            count += 1;
        }
        assert_eq!(count, 25);   
    }

    #[test]
    fn test_ml_kem_decaps_acvp() {
        // test vectors from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json

        let file = File::open("tests/ml_kem_768_decaps.txt").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        let dk = load_value(&mut lines, "dk:").unwrap();

        while let Some(_id) = load_id(&mut lines) {
            dbg!(count);
            let Some(c) = load_value(&mut lines, "c:") else { break };
            let Some(expected_k) = load_value(&mut lines, "k:") else { break };
            let Some(_reason) = load_text(&mut lines, "reason") else { break };

            let mut k = [0u8; 32];

            MlKem768::decaps(
                dk.as_slice().try_into().unwrap(),
                c.as_slice().try_into().unwrap(),
                &mut k
            );
        
            assert_eq!(k, expected_k.as_slice());
            count += 1;
        }
        assert_eq!(count, 10);   
    }
}
