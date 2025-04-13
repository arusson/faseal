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

mod archive;
mod config;
mod identities;
mod utils;
pub mod errors;

pub use archive::{
    FileNode,
    new_archive,
    open_archive,
    DEFAULT_COMPRESSION_LEVEL
};

pub use config::Config;

pub use identities::{
    IdentityPrv,
    IdentityPub,
    keygen,
    change_password
};

#[cfg(target_family="unix")]
const DEFAULT_PUBLIC_PATH: &str = ".faseal/public";
#[cfg(target_family="unix")]
const DEFAULT_PRIVATE_PATH: &str = ".faseal/private";
#[cfg(target_family="unix")]
const CONFIGURATION_FILE: &str = ".faseal/faseal.conf";
#[cfg(target_family="windows")]
const DEFAULT_PUBLIC_PATH: &str = "Documents/faseal/public";
#[cfg(target_family="windows")]
const DEFAULT_PRIVATE_PATH: &str = "Documents/faseal/private";
#[cfg(target_family="windows")]
const CONFIGURATION_FILE: &str = "Documents/faseal/faseal.conf";

const PRIVATE_EXTENSION: &str = "fprv";
const PUBLIC_EXTENSION: &str = "fpub";
const VERSION_FORMAT: &[u8; 4] = &[0, 0, 0, 0];
const MAX_STRING_LENGTH: usize = 65536;
