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

use std::path::PathBuf;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use crate::errors::{Error, Result};
use crate::identities::DEFAULT_MIN_PASSWORD_LENGTH;
use crate::{
    CONFIGURATION_FILE,
    DEFAULT_COMPRESSION_LEVEL,
    DEFAULT_PRIVATE_PATH,
    DEFAULT_PUBLIC_PATH
};

// removes quotes around the path
fn str_to_path(s: &str, is_file: bool) -> Option<PathBuf> {
    let s = s.strip_prefix("\"")?;
    let s = s.strip_suffix("\"")?;
    let path = PathBuf::from(s);
    match is_file && path.is_file() || path.is_dir() {
        true => Some(path),
        false => None
    }
}

fn get_dir(s: &str) -> Result<PathBuf> {
    match dirs::home_dir() {
        Some(home_path) => {
            let dir = home_path.join(s);
            if !dir.exists() {
                std::fs::create_dir_all(&dir)?;
            }
            Ok(dir)
        },
        None => Err(Error::CannotGetHomeDir)
    }
}

fn get_public_dir() -> Result<PathBuf> {
    get_dir(DEFAULT_PUBLIC_PATH)
}

fn get_private_dir() -> Result<PathBuf> {
    get_dir(DEFAULT_PRIVATE_PATH)
}

fn get_configuration_file() -> Result<PathBuf> {
    let mut path = get_dir("")?;
    path.push(CONFIGURATION_FILE);
    Ok(path)
}

pub struct Config {
    main_private_id_path: Option<PathBuf>,
    private_dir_path: PathBuf,
    public_dir_path: PathBuf,
    compression_level: u32,
    min_password_length: usize
}

impl Config {
    const MAIN_PRIVATE_PATH: &str = "main-private-path";
    const PRIVATE_DIR_PATH: &str = "private-dir-path";
    const PUBLIC_DIR_PATH: &str = "public-dir-path";
    const COMPRESSION_LEVEL: &str = "compression-level";
    const MIN_PASSWORD_LENGTH: &str = "min-password-length";

    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            main_private_id_path: None,
            private_dir_path: PathBuf::new(),
            public_dir_path: PathBuf::new(),
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            min_password_length: DEFAULT_MIN_PASSWORD_LENGTH
        }
    }
    
    pub fn new_with_dir_path() -> Result<Self> {
        Ok(Self {
            main_private_id_path: None,
            private_dir_path: get_private_dir()?,
            public_dir_path: get_public_dir()?,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            min_password_length: DEFAULT_MIN_PASSWORD_LENGTH
        })
    }

    pub fn load_config_file() -> Result<Self> {
        let mut config = Self::new_with_dir_path()?;
        if let Ok(file) = File::open(get_configuration_file()?) {
            let lines = BufReader::new(file).lines();
            for line in lines {
                let line = line?;
                config.parse_config_line(&line)?;
            }
        }
        Ok(config)
    }

    pub(crate) fn write_config_file(&self) -> Result<()> {
        let mut content = String::new();
        
        if let Some(path) = self.main_private_id_path.as_ref() {
            let s = format!("{} = \"{}\"\n", Self::MAIN_PRIVATE_PATH, path.to_string_lossy());
            content.push_str(&s);
        }

        if let Ok(defaut_private_path) = get_private_dir() {
            let private_path = self.private_dir_path.to_string_lossy();
            if private_path != defaut_private_path.to_string_lossy() {
                let s = format!("{} = \"{}\"\n", Self::PRIVATE_DIR_PATH, private_path);
                content.push_str(&s);
            }
        }
        
        if let Ok(default_public_path) = get_public_dir() {
            let public_path = self.public_dir_path.to_string_lossy();
            if public_path != default_public_path.to_string_lossy() {
                let s = format!("{} = \"{}\"\n", Self::PUBLIC_DIR_PATH, public_path);
                content.push_str(&s);
            }
        }

        if self.compression_level != DEFAULT_COMPRESSION_LEVEL {
            let s = format!("{} = {}\n", Self::COMPRESSION_LEVEL, self.compression_level);
            content.push_str(&s);
        }

        if self.min_password_length != DEFAULT_MIN_PASSWORD_LENGTH {
            let s = format!("{} = {}\n", Self::MIN_PASSWORD_LENGTH, self.min_password_length);
            content.push_str(&s);
        }

        if !content.is_empty() {
            let mut file = File::create(get_configuration_file()?)?;
            file.write_all(content.as_bytes())?;
        }

        Ok(())
    }

    pub fn main_private_id_path(&self) -> Option<&PathBuf> {
        self.main_private_id_path.as_ref()
    }

    pub(crate) fn set_main_private_id_path(&mut self, path: PathBuf) {
        self.main_private_id_path = Some(path);
    }

    pub(crate) fn private_dir_path(&self) -> &PathBuf {
        &self.private_dir_path
    }

    #[cfg(test)]
    pub(crate) fn set_private_dir_path(&mut self, path: PathBuf) {
        self.private_dir_path = path;
    }

    pub(crate) fn public_dir_path(&self) -> &PathBuf {
        &self.public_dir_path
    }

    #[cfg(test)]
    pub(crate) fn set_public_dir_path(&mut self, path: PathBuf) {
        self.public_dir_path = path
    }

    pub fn compression_level(&self) -> u32 {
        self.compression_level
    }

    pub(crate) fn min_password_length(&self) -> usize {
        self.min_password_length
    }

    fn parse_config_line(&mut self, line: &str) -> Result<()> {
        // comment line
        if line.trim_start().starts_with("#") {
            return Ok(())
        }

        // key = value
        let split = line.splitn(2, "=").collect::<Vec<&str>>();
        if split.len() != 2 {
            return Err(Error::Config("bad configuration line"));
        }

        let key = split[0].trim();
        let value = split[1].trim();
        if key == Self::MAIN_PRIVATE_PATH {
            match str_to_path(value, true) {
                Some(path) => self.main_private_id_path = Some(path),
                None => return Err(Error::Config("main private key path is not a file"))
            }
        }
        else if key == Self::PRIVATE_DIR_PATH {
            match str_to_path(value, false) {
                Some(path) => self.private_dir_path = path,
                None => return Err(Error::Config("private folder path is not a directory")),
            }
        }
        else if key == Self::PUBLIC_DIR_PATH {
            match str_to_path(value, false) {
                Some(path) => self.public_dir_path = path,
                None => return Err(Error::Config("public folder path is not a directory"))
            }
        }
        else if key == Self::COMPRESSION_LEVEL {
            match value.parse::<u32>() {
                Ok(level) if (0..=11).contains(&level) => self.compression_level = level,
                _ => return Err(Error::Config("bad compression level (0-11 expected)"))
            }
        }
        else if key == Self::MIN_PASSWORD_LENGTH {
            match value.parse::<usize>() {
                Ok(length) => self.min_password_length = length,
                Err(_) => return Err(Error::Config("minimal password length is not an integer"))
            }
        }
        else {
            return Err(Error::Config("bad configuration line"))
        }

        Ok(())
    }
}
