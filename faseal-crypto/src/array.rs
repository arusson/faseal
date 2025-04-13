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

// --- Generic array
#[derive(Clone, PartialEq)]
pub struct Array<const N: usize>([u8; N]);

impl<const N: usize> NewArray for Array<N> {
    fn new() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> AsSlice for Array<N> {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> AsMut<[u8; N]> for Array<N> {
    fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8; N]> for Array<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for Array<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

// --- Generic array with zeroize on drop
#[derive(Clone)]
pub struct ZeroizeArray<const N: usize>([u8; N]);

impl<const N: usize> NewArray for ZeroizeArray<N> {
    fn new() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> AsSlice for ZeroizeArray<N> {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> From<[u8; N]> for ZeroizeArray<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> AsMut<[u8; N]> for ZeroizeArray<N> {
    fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8; N]> for ZeroizeArray<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> ZeroizeOnDrop for ZeroizeArray<N> {}
