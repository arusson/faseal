# FaSEAL

**FaSEAL** (pronounced like "facile" if you're french, meaning "easy") is a simple archive encryption tool with classic and post-quantum cryptographic mechanisms.

Its main function is to securely share files and folders with recipients:
- files and recipients are confidential;
- each archive is signed (can be verified only by the recipients).

## Installation

If you want to compile, download the source code and run from the main directory of the project:
```
cargo build --release
mv target/release/faseal ~/.local/bin/
```

It can be installed globally on your system if you have enough privileges:
```
sudo mv target/release/faseal /usr/local/bin/
```

## Usage

The binary contains several commands:
```
Usage: faseal [COMMAND]

Commands:
  create   Create a new encrypted archive
  extract  Extract an encrypted archive
  list     List recipients and files of an encrypted archive
  keygen   Generate a key pair
  passwd   Change private key password
  keyinfo  Dump info of a private/public key
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Key generation

A new key pair can be created with the `keygen` subcommand.
```
Generate a key pair

Usage: faseal keygen [OPTIONS] --name <name>

Options:
  -n, --name <name>        Identity of the owner
  -c, --contact <contact>  Contact of the owner (e.g., email) [default: ]
      --comment <comment>  Comment [default: ]
  -m <cost_m>              Memory usage in kiB for Argon2 (default: 16384)
  -p <cost_p>              Parallelism cost for Argon2 (default: 1)
  -t <cost_t>              Number of iterations for Argon2 (default: 3)
  -h, --help               Print help
```

The only required argument is the name.
Beware, the user information cannot be changed.

A password with at least 12 characters is required (UTF-8 encoding) to protect the private key.

Once created, the private and public keys are written in the default folders:
- Private keys: `~/.faseal/private/` (UNIX targets), `%USERPROFILE%\Document\faseal\private\` (Windows)
- Public keys: `~/.faseal/public/` (UNIX targets), `%USERPROFILE%\Document\faseal\public\` (Windows)

The private key that was just generated can be configured as default for archive creation/opening (proposed in a prompt).

### Archive creation

An archive can be created with the `create` subcommand.
```
Create a new encrypted archive

Usage: faseal create [OPTIONS] --output <output> [files]...

Arguments:
  [files]...  Files and folder to add to the archive

Options:
  -k, --private <private key>      Path to your private key
  -p, --public <public keys>       Public key of a recipient
  -o, --output <output>            Output file path
  -q, --compression <compression>  Compression level (0-11) (default: 9)
  -h, --help                       Print help
```

The only required argument is the file name for the output.
It can be followed by file or folder names.

If no private key is configured to be used as default, then its path must be provided with the `-k` option.

Recipients can be added with the `-p` option (one for each recipient).

### Archive extraction

An encrypted archive can be extracted with the `extract` subcommand.
```
Extract an encrypted archive

Usage: faseal extract [OPTIONS] <archive>

Arguments:
  <archive>  Encrypted archive path

Options:
  -k, --private <private key>  Path to your private key
  -o, --output <output>        Output file path
  -h, --help                   Print help
```

The only required argument is an archive path.
If no output path is provided, the default one is based on the original archive file name (an archive `archive.sealed` will be decrypted to the folder `archive.d`).

If no private key is configured to be used as default, then its path must be provided with the `-k` option.

### Other subcommands

Three other subcommands are provided:
- `list`: only to list file names and recipients of an archive;
- `passwd`: change password of a private key;
- `keyinfo`: dump information on a public or private key, can be used to dump the public keys (verifying and encapsulation keys) as hexadecimal strings.

## Configuration

The configuration file is located at:
- `~/.faseal/faseal.conf` (UNIX targets);
- `%USERPROFILE%\Documents\faseal\faseal.conf` (Windows).

Customized values are:
- `main-private-path`: default private key file for archive creation/opening;
- `private-dir-path`: default folder for private keys (default: `/home/user/.faseal/private/` or `%USERPROFILE%\Documents\faseal\private\` depending of the OS);
- `public-dir-path`: default folder for public keys (default: `/home/user/.faseal/public/` or `%USERPROFILE%\Documents\faseal\public\` depending of the OS);
- `compression-level`: default compression level (default: 9);
- `min-password-length`: default minimum password length (default: 12).

Example:
```
main-private-path = "/path/to/NAME_95ff9626-e6e2-4df9-a758-3ba395b05042.fprv"
private-dir-path = "/path/to/private/"
public-dir-path = "/path/to/public/"
compression-level = 7
min-password-length = 16
```

## Specifications

Cryptographic mechanisms and file formats are described in the [SPECIFICATIONS](./SPECIFICATIONS.md).

## Limitation and security

This is a personal project and **it is not recommended to rely on it in a production environment**.
Use it with caution.

Please email me at `faseal at free.fr` in case of a potential security issue.
I'll try my best to address the issue.

## Future updates

The main future features are as follows:
- Version 0.X:
  * public key trust store (list of trusted public keys associated to the user private key);
  * anonymous recipients mode.
- Version 1.X: graphical interface with either [GTK](https://gtk-rs.org/) or [iced](https://iced.rs/);
- Version 2.X: certificate chain support (?).

## License

This program is free software and is distributed under the [GPLv3 License](./LICENSE).

```
FaSEAL, a simple archive encryption tool
Copyright (C) 2025 A. Russon

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
