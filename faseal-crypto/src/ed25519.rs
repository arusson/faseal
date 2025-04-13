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

use crate::{
    curve25519::{
        points::Point,
        scalar::{
            scalar_is_canonical,
            scalar_muladd,
            scalar_reduce
        },
        scalarmult::{
            scalarmult_double,
            scalarmult_ed25519_base
        }
    },
    hashes::sha512::Sha512,
    traits::sigt::{
        Error,
        Result
    }
};

pub(crate) struct Ed25519;

impl Ed25519 {
    pub(crate) const SIG_LEN: usize = 64;
    pub(crate) const SK_LEN: usize = 32;
    pub(crate) const VK_LEN: usize = 32;

    pub(crate) fn keygen_internal(
        seed: &[u8; 32],
        signing_key: &mut [u8; Self::SK_LEN],
        verifying_key: &mut [u8; Self::VK_LEN]
    ) {
        let mut h = Sha512::hash(seed);
        h[0]  &= 248;
        h[31] &= 127;
        h[31] |= 64;
        *verifying_key = scalarmult_ed25519_base(&h[..32].try_into().unwrap()).bytes();
        signing_key.copy_from_slice(seed);
        h.zeroize();
    }

    pub(crate) fn sign(
        signing_key: &[u8; Self::SK_LEN],
        verifying_key: &[u8; Self::VK_LEN],
        message: &[&[u8]]
    ) -> [u8; Self::SIG_LEN] {
        // 1. Hash the private key, 32 octets, using SHA-512.  Let h denote the
        //    resulting digest.  Construct the secret scalar s from the first
        //    half of the digest, and the corresponding public key A, as
        //    described in the previous section.  Let prefix denote the second
        //    half of the hash digest, h[32],...,h[63].
        let mut h = Sha512::hash(signing_key);
        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        let prefix = &h[32..];

        // 2. Compute SHA-512(dom2(F, C) || prefix || PH(M)), where M is the
        //    message to be signed.  Interpret the 64-octet digest as a little-
        //    endian integer r.
        let mut sha = Sha512::init();
        sha.update(prefix);
        for &m in message {
            sha.update(m);
        }
        let mut nonce_large = sha.finalize();
        h.zeroize();

        // 3. Compute the point [r]B.  For efficiency, do this by first
        //    reducing r modulo L, the group order of B.  Let the string R be
        //    the encoding of this point.
        let mut nonce = scalar_reduce(&nonce_large);
        nonce_large.zeroize();
    
        let r_point = scalarmult_ed25519_base(&nonce);
        let sig_r = r_point.bytes();

        // 4. Compute SHA512(dom2(F, C) || R || A || PH(M)), and interpret the
        //    64-octet digest as a little-endian integer k.
        let mut sha = Sha512::init();
        sha.update(&sig_r);
        sha.update(verifying_key);
        for &m in message {
            sha.update(m);
        }
        let hram = sha.finalize();
        let k = scalar_reduce(&hram);
    
        // 5. Compute S = (r + k * s) mod L.  For efficiency, again reduce k
        //    modulo L first.
        s[0]  &= 248;
        s[31] &= 127;
        s[31] |= 64;
        let sig_s = scalar_muladd(&k, &s, &nonce);
        s.zeroize();
        nonce.zeroize();
    
        // 6. Form the signature of the concatenation of R (32 octets) and the
        //    little-endian encoding of S (32 octets; the three most
        //    significant bits of the final octet are always zero).
        let mut signature = [0u8; Self::SIG_LEN];
        signature[0..32].copy_from_slice(&sig_r[..32]);
        signature[32..64].copy_from_slice(&sig_s[..32]);
        signature
    }

    pub(crate) fn verify(
        verifying_key: &[u8; Self::VK_LEN],
        message: &[&[u8]],
        sig: &[u8; Self::SIG_LEN]
    ) -> Result<()> {
        // 1.  To verify a signature on a message M using public key A, with F
        //    being 0 for Ed25519ctx, 1 for Ed25519ph, and if Ed25519ctx or
        //    Ed25519ph is being used, C being the context, first split the
        //    signature into two 32-octet halves.  Decode the first half as a
        //    point R, and the second half as an integer S, in the range
        //    0 <= s < L.  Decode the public key A as point A'.  If any of the
        //    decodings fail (including S being out of range), the signature is
        //    invalid.
        let sig_s = &sig.as_ref()[32..];
        if (sig_s[31] & 240) != 0 && !scalar_is_canonical(sig_s.try_into().unwrap()) {
            return Err(Error::InvalidSignature);
        }

        let public_point = match Point::from_bytes_negate_vartime(verifying_key) {
            Ok(point) if !point.has_small_order() => point,
            _ => return Err(Error::InvalidPublicKey),
        };

        let sig_r = &sig.as_ref()[..32];
        let expected_r = match Point::try_from(&sig_r.try_into().unwrap()) {
            Ok(point) if !point.has_small_order() => point,
            _ => return Err(Error::InvalidSignature),
        };

        // 2. Compute SHA512(dom2(F, C) || R || A || PH(M)), and interpret the
        //    64-octet digest as a little-endian integer k.
        let mut sha = Sha512::init();
        sha.update(sig_r);
        sha.update(verifying_key);
        for &m in message {
            sha.update(m);
        }
        let hram = sha.finalize();
        let k = scalar_reduce(&hram);

        // 3. Check the group equation [8][S]B = [8]R + [8][k]A'.  It's
        //    sufficient, but not required, to instead check [S]B = R + [k]A'.
        let mut check = scalarmult_double(sig_s.try_into().unwrap(), &k, &public_point);
        check -= &expected_r;
        match check.has_small_order() {
            true => Ok(()),
            false => Err(Error::InvalidSignature),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use hex_literal::hex;

    #[test]
    fn test_ed25519_1() {
        let msg = b"bonjour";
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let mut sk = [0u8; Ed25519::SK_LEN];
        let mut vk = [0u8; Ed25519::VK_LEN];
        Ed25519::keygen_internal(&seed, &mut sk, &mut vk);
        let sig = Ed25519::sign(&sk, &vk, &[msg]);
        assert!(Ed25519::verify(&vk, &[msg], &sig).is_ok());
    }

    struct Ed25519Vector {
        sk: [u8; 32],
        vk: [u8; 32],
        msg: &'static [u8],
        sig: [u8; 64]
    }

    #[test]
    fn test_ed25519_rfc() {
        // source: https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
        let test_vector_0 = Ed25519Vector {
            sk: hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
            vk: hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            msg: b"",
            sig: hex!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
                5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        };

        let test_vector_1 = Ed25519Vector {
            sk: hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
            vk: hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            msg: b"\x72",
            sig: hex!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
                085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            )
        };

        let test_vector_2 = Ed25519Vector {
            sk: hex!("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
            vk: hex!("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
            msg: b"\xaf\x82",
            sig: hex!(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac
                18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            )
        };
    
        let test_vector_1024 = Ed25519Vector {
            sk: hex!("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"),
            vk: hex!("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"),
            msg: &hex!(
                "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98
                fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8
                79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d
                658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc
                1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe
                ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e
                06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef
                efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7
                aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1
                85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2
                d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24
                554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270
                88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc
                2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07
                07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba
                b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a
                ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e
                c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7
                51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c
                42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8
                ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df
                f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08
                d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649
                de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4
                88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3
                2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e
                6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f
                b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5
                0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1
                369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d
                b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c
                0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
            ),
            sig: hex!(
                "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350
                aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
            )
        };

        let test_vector_sha = Ed25519Vector {
            sk: hex!("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"),
            vk: hex!("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
            msg: &hex!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a
                2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            ),
            sig: hex!(
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589
                09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
            )
        };
    
        let test_vectors = [
            &test_vector_0,
            &test_vector_1,
            &test_vector_2,
            &test_vector_1024,
            &test_vector_sha
        ];
    
        for vector in test_vectors {
            let sig = Ed25519::sign(&vector.sk, &vector.vk, &[&vector.msg]);
            assert_eq!(sig, vector.sig);
            assert!(Ed25519::verify(&vector.vk, &[&vector.msg], &vector.sig).is_ok());
        }
    }
}
