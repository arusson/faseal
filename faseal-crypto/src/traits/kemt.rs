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
    InvalidDecapsulationKey,
    InvalidEncapsulationKey,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDecapsulationKey => write!(f, "KEM: invalid decapsulation key."),
            Self::InvalidEncapsulationKey => write!(f, "KEM: invalid encapsulation key."),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

// --- KEM trait ---

pub trait ToEncapsKeyT<DK> {
    fn to_encaps_key(&self) -> DK;
}

pub trait KemT {
    const CIPHERTEXT_LEN: usize;
    const DECAPSKEY_LEN: usize;
    const ENCAPSKEY_LEN: usize;
    const SHARED_LEN: usize = 32; // support for KEM with 256-bit shared secret only

    type Ciphertext: NewArray + AsSlice;
    type DecapsKey: NewArray + AsSlice + ZeroizeOnDrop + ToEncapsKeyT<Self::EncapsKey>;
    type EncapsKey: NewArray + PartialEq + AsSlice + Clone;
    type SymmetricKey: ZeroizeOnDrop + AsRef<[u8; 32]>;

    fn keygen() -> (Self::EncapsKey, Self::DecapsKey);
    fn encaps(encaps_key: &Self::EncapsKey) -> (Self::SymmetricKey, Self::Ciphertext);
    fn decaps(decaps_key: &Self::DecapsKey, ciphertext: &Self::Ciphertext) -> Self::SymmetricKey;

    fn validate_encaps_key(encaps_key: &Self::EncapsKey) -> Result<()>;
    fn validate_decaps_key(decaps_key: &Self::DecapsKey) -> Result<()>;
}
