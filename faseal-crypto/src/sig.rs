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

use rand::RngCore;
use zeroize::Zeroize;

use crate::{
    ed25519::Ed25519,
    ml_dsa::MlDsa65,
    array::{
        Array,
        ZeroizeArray
    },
    traits::{
        arrayt::NewArray,
        sigt::{
            SigT,
            ToVerifyingKeyT,
            Result
        }
    }
};

pub struct MlDsa65Ed25519;

fn sig_keygen_derand(
    m_seed: &[u8; 32],
    e_seed: &[u8; 32],
    signing_key: &mut <MlDsa65Ed25519 as SigT>::SigningKey,
    verifying_key: &mut <MlDsa65Ed25519 as SigT>::VerifyingKey
) {
    let (m_sk, e_sk) = signing_key.as_mut().split_at_mut(MlDsa65::SK_LEN + MlDsa65::VK_LEN);
    let (m_vk, e_vk) = verifying_key.as_mut().split_at_mut(MlDsa65::VK_LEN);

    // ML-DSA key generation
    MlDsa65::keygen_internal(
        m_seed,
        m_sk[..MlDsa65::SK_LEN].as_mut().try_into().unwrap(),
        m_vk.try_into().unwrap()
    );
    m_sk[MlDsa65::SK_LEN..].copy_from_slice(m_vk);

    // Ed25519 key generation
    Ed25519::keygen_internal(
        e_seed,
        e_sk[..Ed25519::SK_LEN].as_mut().try_into().unwrap(),
        e_vk.try_into().unwrap()
    );
    e_sk[Ed25519::SK_LEN..].copy_from_slice(e_vk);
}

impl ToVerifyingKeyT<<MlDsa65Ed25519 as SigT>::VerifyingKey>
    for <MlDsa65Ed25519 as SigT>::SigningKey
{
    fn to_verifying_key(&self) -> <MlDsa65Ed25519 as SigT>::VerifyingKey {
        // get verifying keys from the copies in the signing keys
        let m_vk_ref = &self.as_ref()[
            MlDsa65::SK_LEN..MlDsa65::SK_LEN + MlDsa65::VK_LEN
        ];
        let offset = MlDsa65::SK_LEN + MlDsa65::VK_LEN + 32;
        let e_vk_ref = &self.as_ref()[offset..offset + 32];
    
        // split the verifying key
        let mut verifying_key = <MlDsa65Ed25519 as SigT>::VerifyingKey::new();
        let (m_vk, e_vk) = verifying_key.as_mut().split_at_mut(MlDsa65::VK_LEN);

        // verifying key from ML-DSA
        m_vk.copy_from_slice(m_vk_ref);

        // verifying key from Ed25519
        e_vk.copy_from_slice(e_vk_ref);

        verifying_key
    }
}

impl SigT for MlDsa65Ed25519 {
    const SIGNATURE_LEN: usize = MlDsa65::SIG_LEN + Ed25519::SIG_LEN;
    // individual verifying keys are included in the signing key to make is easier
    // to be extracted from the secret key, and Ed25519 verifying key is needed
    // for signature generation
    const SIGNINGKEY_LEN: usize = MlDsa65::SK_LEN + MlDsa65::VK_LEN
        + Ed25519::SK_LEN + Ed25519::VK_LEN;
    const VERIFYINGKEY_LEN: usize = MlDsa65::VK_LEN + Ed25519::VK_LEN;

    type Signature = Array<{ Self::SIGNATURE_LEN }>;
    type SigningKey = ZeroizeArray<{ Self::SIGNINGKEY_LEN }>;
    type VerifyingKey = Array<{ Self::VERIFYINGKEY_LEN }>;

    fn keygen() -> (Self::SigningKey, Self::VerifyingKey) {
        let mut signing_key = <MlDsa65Ed25519 as SigT>::SigningKey::new();
        let mut verifying_key = <MlDsa65Ed25519 as SigT>::VerifyingKey::new();

        // ML-DSA and Ed25519 seeds
        let mut m_seed = [0u8; 32];
        let mut e_seed = [0u8; 32];
        rand::rng().fill_bytes(m_seed.as_mut());
        rand::rng().fill_bytes(e_seed.as_mut());

        // generation
        sig_keygen_derand(&m_seed, &e_seed, &mut signing_key, &mut verifying_key);
        m_seed.zeroize();
        e_seed.zeroize();

        (signing_key, verifying_key)
    }

    // strong nesting hybrid signature
    fn sign(signing_key: &Self::SigningKey, msg: &[u8]) -> Self::Signature {
        // split signing keys
        let (m_skvk, e_skvk) = signing_key.as_ref().split_at(MlDsa65::SK_LEN + MlDsa65::VK_LEN);
        let m_sk = &m_skvk[..MlDsa65::SK_LEN];
        let (e_sk, e_vk) = e_skvk.split_at(Ed25519::SK_LEN);

        // ML-DSA signature: signs the original message
        let m_sig = MlDsa65::sign(m_sk.try_into().unwrap(), msg, b"");

        // Ed25519 signature: signs the original message _and_ ML-DSA signature 
        let e_sig = Ed25519::sign(
            e_sk.try_into().unwrap(),
            e_vk.try_into().unwrap(),
            &[msg, &m_sig]
        );

        // combine signatures
        let mut signature = <MlDsa65Ed25519 as SigT>::Signature::new();
        signature.as_mut()[..MlDsa65::SIG_LEN].copy_from_slice(&m_sig);
        signature.as_mut()[MlDsa65::SIG_LEN..].copy_from_slice(&e_sig);
        signature
    }

    fn verify(
        verifying_key: &Self::VerifyingKey,
        msg: &[u8],
        sig: &Self::Signature
    ) -> Result<()> {
        // split verifying keys
        let (m_vk, e_vk) = verifying_key.as_ref().split_at(MlDsa65::VK_LEN);

        // split signatures
        let (m_sig, e_sig) = sig.as_ref().split_at(MlDsa65::SIG_LEN);
    
        // verify ML-DSA signature
        MlDsa65::verify(m_vk.try_into().unwrap(), msg, m_sig.try_into().unwrap(), b"")?;

        // verify Ed25519 signature
        Ed25519::verify(e_vk.try_into().unwrap(), &[msg, m_sig], e_sig.try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MlDsa65Ed25519,
        SigT
    };
    use crate::hashes::sha3::Sha3_256;

    #[test]
    fn test_sig() {
        let (sk, vk) = MlDsa65Ed25519::keygen();

        let msg = Sha3_256::hash(&[b"hello"]);
        let badmsg = Sha3_256::hash(&[b"bye"]);

        let signature = MlDsa65Ed25519::sign(&sk, &msg);
        assert!(MlDsa65Ed25519::verify(&vk, &msg, &signature).is_ok());
        assert!(MlDsa65Ed25519::verify(&vk, &badmsg, &signature).is_err());
    }
}
