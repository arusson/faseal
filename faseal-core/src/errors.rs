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

use faseal_crypto::argon2;
use faseal_crypto::aead;
use faseal_crypto::traits::kemt;
use faseal_crypto::traits::sigt;

#[derive(Debug)]
pub enum Error {
    // common errors
    Io(std::io::Error),
    FileNotFound(std::path::PathBuf),
    CannotCreateFile(std::path::PathBuf),
    UTF8(std::string::FromUtf8Error),
    CannotGetHomeDir,
    InvalidLength,

    // crypto errors
    Argon2(argon2::Error),
    Aead(aead::Error),
    Signature(sigt::Error),
    Kem(kemt::Error),

    // identities
    NotPrivateId,
    PrivateIdUnsupportedVersion,
    PrivateIdCorrupted,
    NotPublicId,
    PublicIdUnsupportedVersion,
    PublicIdCorrupted,

    // password
    PasswordTooShort(usize),
    ConfirmationPasswordDoesNotMatch,

    // archive
    Archive(&'static str),
    Duplicate(String),
    ArchiveCorrupted,

    // configuration
    Config(&'static str),

    UnknownProblem
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<argon2::Error> for Error {
    fn from(value: argon2::Error) -> Self {
        Self::Argon2(value)
    }
}

impl From<aead::Error> for Error {
    fn from(value: aead::Error) -> Self {
        Self::Aead(value)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::UTF8(value)
    }
}

impl From<sigt::Error> for Error {
    fn from(value: sigt::Error) -> Self {
        Self::Signature(value)
    }
}

impl From<kemt::Error> for Error {
    fn from(value: kemt::Error) -> Self {
        Self::Kem(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::FileNotFound(path) => write!(f, "File \"{}\" not found.", path.display()),
            Self::CannotCreateFile(path) => write!(
                f,
                "File \"{}\" cannot be created.",
                path.display()
            ),
            Self::UTF8(err) => write!(f, "{err}"),
            Self::CannotGetHomeDir => write!(f, "Cannot retrieve home path."),
            Self::InvalidLength => write!(f, "Invalid length."),

            // crypto errors
            Self::Argon2(err) => write!(f, "{err}"),
            Self::Aead(err) => write!(f, "{err}"),
            Self::Signature(err) => write!(f, "{err}"),
            Self::Kem(err) => write!(f, "{err}"),
        
            // identities
            Self::NotPrivateId => write!(f, "Private identity: not a private identity file"),
            Self::PrivateIdUnsupportedVersion => write!(f, "Private identity: unsupported version"),
            Self::PrivateIdCorrupted => write!(f, "Private identity: corrupted"),
            Self::NotPublicId => write!(f, "Public identity: not a public identity file"),
            Self::PublicIdUnsupportedVersion => write!(f, "Public identity: unsupported version"),
            Self::PublicIdCorrupted => write!(f, "Public identity: corrupted"),

            // password
            Self::PasswordTooShort(l) => write!(f, "Password: too short (min: {l} characters)"),
            Self::ConfirmationPasswordDoesNotMatch => write!(
                f, "Password: confirmation password does not match"
            ),

            // archive
            Self::Archive(s) => write!(f, "Archive: {s}."),
            Self::Duplicate(s) => write!(
                f,
                "Archive: two files/folders with the same name (\"{}\").",
                s
            ),
            Self::ArchiveCorrupted => write!(f, "Archive: corrupted"),

            Self::Config(s) => write!(f, "Configuration: {s}."),
        
            Self::UnknownProblem => write!(f, "Unknown problem, ask an expert.")
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
