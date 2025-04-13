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

// adapted from https://github.com/PQClean/PQClean/tree/master/crypto_sign/ml-dsa-65/clean

mod internals;
mod poly;
mod polyvec;

use rand::RngCore;
use zeroize::Zeroize;

use crate::traits::sigt::Result;

const ML_DSA_N: usize = 256;
const ML_DSA_K: usize = 6;
const ML_DSA_L: usize = 5;
const ML_DSA_Q:   i32 = 8_380_417;
const QINV:       i32 = 58_728_449;   // q^-1 mod 2^32
const GAMMA_1:    i32 = 1 << 19;
const GAMMA_2:    i32 = (ML_DSA_Q - 1) / 32;
const BETA:       i32 = ETA * (TAU as i32);
const ETA:        i32 = 4;
const OMEGA:    usize = 55;
const TAU:      usize = 49;
const LAMBDA4:  usize = 48; // lambda / 4

pub(crate) struct MlDsa65;

impl MlDsa65 {
    pub(crate) const SIG_LEN: usize = 3309;
    pub(crate) const SK_LEN: usize = 4032;
    pub(crate) const VK_LEN: usize = 1952;

    // ctx must be 255 bytes or less to be compliant
    // it is verified in the hybrid signature call
    pub(crate) fn sign(
        signing_key: &[u8; Self::SK_LEN],
        message: &[u8],
        ctx: &[u8]
    ) -> [u8; Self::SIG_LEN] {
        let mut rnd = [0u8; 32];
        rand::rng().fill_bytes(&mut rnd);
        let signature = Self::sign_internal(signing_key, message, &rnd, &[0, ctx.len() as u8], ctx);
        rnd.zeroize();
        signature
    }

    // ctx must be 255 bytes or less to be compliant
    // it is verifed in the hybrid signature call
    pub(crate) fn verify(
        verifying_key: &[u8; Self::VK_LEN],
        message: &[u8],
        sig: &[u8; Self::SIG_LEN],
        ctx: &[u8]
    ) -> Result<()> {
        Self::verify_internal(verifying_key, message, sig, &[0, ctx.len() as u8], ctx)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Lines};
    use rand::RngCore;
    use super::MlDsa65;

    #[test]
    fn test_ml_dsa() {
        let mut sk = [0u8; MlDsa65::SK_LEN];
        let mut vk = [0u8; MlDsa65::VK_LEN];
        let message = b"Testing ML-DSA";

        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        MlDsa65::keygen_internal(&seed, &mut sk, &mut vk);
        let signature = MlDsa65::sign(&sk, message, &[]);
        assert!(MlDsa65::verify(&vk, message, &signature, &[]).is_ok());
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
    fn test_ml_dsa_keygen_acvp() {
        // test vectors from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json

        let file = File::open("tests/ml_dsa_65_keygen.txt").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(_id) = load_id(&mut lines) {
            dbg!(count);
            let Some(seed) = load_value(&mut lines, "seed:") else { break };
            let Some(expected_pk) = load_value(&mut lines, "pk:") else { break };
            let Some(expected_sk) = load_value(&mut lines, "sk:") else { break };

            let mut pk = [0u8; MlDsa65::VK_LEN];
            let mut sk = [0u8; MlDsa65::SK_LEN];
            MlDsa65::keygen_internal(
                seed.as_slice().try_into().unwrap(),
                &mut sk,
                &mut pk
            );
            assert_eq!(sk, expected_sk.as_slice());
            assert_eq!(pk, expected_pk.as_slice());
            count += 1;
        }
        assert_eq!(count, 25);
    }

    #[test]
    fn test_ml_dsa_sign_external_acvp() {
        // test vectors from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json

        let file = File::open("tests/ml_dsa_65_sign_external.txt").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(_id) = load_id(&mut lines) {
            dbg!(count);
            let Some(message) = load_value(&mut lines, "message:") else { break };
            let Some(rnd) = load_value(&mut lines, "rnd:") else { break };
            let Some(sk) = load_value(&mut lines, "sk:") else { break };
            let Some(ctx) = load_value(&mut lines, "context:") else { break };
            let Some(expected_sig) = load_value(&mut lines, "signature:") else { break };

            // external call includes context
            let sig = MlDsa65::sign_internal(
                sk.as_slice().try_into().unwrap(),
                &message,
                rnd.as_slice().try_into().unwrap(),
                &[0, ctx.len() as u8],
                ctx.as_slice().try_into().unwrap()
            );
            assert_eq!(sig, expected_sig.as_slice());
            count += 1;
        }
        assert_eq!(count, 15);
    }

    #[test]
    fn test_ml_dsa_sign_external_det_acvp() {
        // test vectors from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json

        let file = File::open("tests/ml_dsa_65_sign_external_det.txt").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(_id) = load_id(&mut lines) {
            dbg!(count);
            let Some(message) = load_value(&mut lines, "message:") else { break };
            let Some(sk) = load_value(&mut lines, "sk:") else { break };
            let Some(ctx) = load_value(&mut lines, "context:") else { break };
            let Some(expected_sig) = load_value(&mut lines, "signature:") else { break };

            // external call includes context
            // rand is [0; 32] for deterministic variant
            let sig = MlDsa65::sign_internal(
                sk.as_slice().try_into().unwrap(),
                &message,
                &[0; 32],
                &[0, ctx.len() as u8],
                ctx.as_slice().try_into().unwrap()
            );
            assert_eq!(sig, expected_sig.as_slice());
            count += 1;
        }
        assert_eq!(count, 15);
    }

    #[test]
    fn test_ml_dsa_sign_internal_acvp() {
        // test vectors from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json

        let file = File::open("tests/ml_dsa_65_sign_internal.txt").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(_id) = load_id(&mut lines) {
            dbg!(count);
            let Some(message) = load_value(&mut lines, "message:") else { break };
            let Some(rnd) = load_value(&mut lines, "rnd:") else { break };
            let Some(sk) = load_value(&mut lines, "sk:") else { break };
            let Some(expected_sig) = load_value(&mut lines, "signature:") else { break };

            // external call includes context
            let sig = MlDsa65::sign_internal(
                sk.as_slice().try_into().unwrap(),
                &message,
                rnd.as_slice().try_into().unwrap(),
                &[],
                &[]
            );
            assert_eq!(sig, expected_sig.as_slice());
            count += 1;
        }
        assert_eq!(count, 15);
    }

    #[test]
    fn test_ml_dsa_sign_internal_det_acvp() {
        // test vectors from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json

        let file = File::open("tests/ml_dsa_65_sign_internal_det.txt").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(_id) = load_id(&mut lines) {
            dbg!(count);
            let Some(message) = load_value(&mut lines, "message:") else { break };
            let Some(sk) = load_value(&mut lines, "sk:") else { break };
            let Some(expected_sig) = load_value(&mut lines, "signature:") else { break };

            // no context for internal call
            // rand is [0; 32] for deterministic variant
            let sig = MlDsa65::sign_internal(
                sk.as_slice().try_into().unwrap(),
                &message,
                &[0; 32],
                &[],
                &[]
            );
            assert_eq!(sig, expected_sig.as_slice());
            count += 1;
        }
        assert_eq!(count, 15);
    }

    #[test]
    fn test_ml_dsa_verify_external_acvp() {
        // test vectors from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json

        let file = File::open("tests/ml_dsa_65_verify_external.txt").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(_id) = load_id(&mut lines) {
            dbg!(count);
            let Some(passed) = load_text(&mut lines, "testPassed: ") else { break };
            let Some(pk) = load_value(&mut lines, "pk: ") else { break };
            let Some(message) = load_value(&mut lines, "message: ") else { break };
            let Some(context) = load_value(&mut lines, "context: ") else { break };
            let Some(signature) = load_value(&mut lines, "signature:") else { break };
            let Some(_reason) = load_text(&mut lines, "reason:") else { break };

            // no prefix to the message for these test vectors
            let res = MlDsa65::verify_internal(
                pk.as_slice().try_into().unwrap(),
                &message,
                signature.as_slice().try_into().unwrap(),
                &[0, context.len() as u8],
                &context
            );
        
            if passed.eq("true") {
                assert!(res.is_ok());
            }
            else {
                assert!(res.is_err());
            }
            count += 1;
        }
        assert_eq!(count, 15);
    }

    #[test]
    fn test_ml_dsa_verify_internal_acvp() {
        // test vectors from https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json

        let file = File::open("tests/ml_dsa_65_verify_internal.txt").unwrap();
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(_id) = load_id(&mut lines) {
            dbg!(count);
            let Some(passed) = load_text(&mut lines, "testPassed: ") else { break };
            let Some(pk) = load_value(&mut lines, "pk: ") else { break };
            let Some(message) = load_value(&mut lines, "message: ") else { break };
            let Some(signature) = load_value(&mut lines, "signature:") else { break };
            let Some(_reason) = load_text(&mut lines, "reason:") else { break };

            // no prefix to the message for these test vectors
            let res = MlDsa65::verify_internal(
                pk.as_slice().try_into().unwrap(),
                &message,
                signature.as_slice().try_into().unwrap(),
                &[],
                &[]
            );
        
            if passed.eq("true") {
                assert!(res.is_ok());
            }
            else {
                assert!(res.is_err());
            }
            count += 1;
        }
        assert_eq!(count, 15);
    }
}
