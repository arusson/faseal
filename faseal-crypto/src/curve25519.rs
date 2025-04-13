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

// this implementation of Curve25519 is adapted from the C code of libsodium:
// https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c

mod base;
mod field;
pub(crate) mod points;
pub(crate) mod scalar;
pub(crate) mod scalarmult;
