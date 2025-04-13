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

use zeroize::ZeroizeOnDrop;

use crate::traits::arrayt::{
    AsSlice,
    NewArray
};

#[derive(Debug)]
pub enum Error {
    InvalidSignature,
    InvalidPublicKey,
    ContextTooLong
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "Signature: invalid signature."),
            Self::InvalidPublicKey => write!(f, "Signature: invalid verifying key."),
            Self::ContextTooLong   => write!(f, "Signature: too long.")
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

// --- Signature traits ---

pub trait ToVerifyingKeyT<VK> {
    fn to_verifying_key(&self) -> VK;
}

pub trait SigT {
    const SIGNATURE_LEN: usize;
    const SIGNINGKEY_LEN: usize;
    const VERIFYINGKEY_LEN: usize;

    type Signature: NewArray + PartialEq + AsSlice + Clone;
    type SigningKey: NewArray + AsSlice + ZeroizeOnDrop + ToVerifyingKeyT<Self::VerifyingKey>;
    type VerifyingKey: NewArray + PartialEq + AsSlice + Clone;

    fn keygen() -> (Self::SigningKey, Self::VerifyingKey);
    fn sign(signing_key: &Self::SigningKey, msg: &[u8]) -> Self::Signature;
    fn verify(
        verifying_key: &Self::VerifyingKey,
        msg: &[u8],
        sig: &Self::Signature
    ) -> Result<()>;
}
