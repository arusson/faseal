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
use std::io::Write;

use faseal_core::{
    FileNode,
    DEFAULT_COMPRESSION_LEVEL,
    Config
};

use faseal_crypto::argon2::Argon2Params;

use rpassword::prompt_password;
use secrecy::SecretString;

use clap::{
    Arg,
    ArgAction,
    ArgGroup,
    ArgMatches,
    Command,
    value_parser,
};

// KEM and SIG algorithms
type Kem = faseal_crypto::kem::MlKem768X25519;
type Sig = faseal_crypto::sig::MlDsa65Ed25519;
type IdentityPrv = faseal_core::IdentityPrv<Kem, Sig>;
type IdentityPub = faseal_core::IdentityPub<Kem, Sig>;

const FASEAL_VERSION: &str = env!("CARGO_PKG_VERSION");

enum FaSEALError {
    Io(std::io::Error),
    CoreError(faseal_core::errors::Error),
    CliError(&'static str),
    FileNotFound(PathBuf),
    FileOrDirNotFound(PathBuf),
    FileAlreadyExists(PathBuf),
    DirCannotCreate(PathBuf, std::io::Error),
}

impl From<std::io::Error> for FaSEALError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<faseal_core::errors::Error> for FaSEALError {
    fn from(value: faseal_core::errors::Error) -> Self {
        Self::CoreError(value)
    }
}

impl std::fmt::Display for FaSEALError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::CliError(s) => write!(f, "{s}"),
            Self::CoreError(e) => write!(f, "{e}"),
            Self::FileNotFound(p) => write!(f, "File \"{}\" not found.", p.display()),
            Self::FileOrDirNotFound(p) => write!(
                f, "File or directory \"{}\" not found.", p.display()
            ),
            Self::FileAlreadyExists(p) => write!(
                f, "File \"{}\" already exists.", p.display()
            ),
            Self::DirCannotCreate(p, e) => write!(
                f, "Cannot create directory \"{}\" ({}).", p.display(), e
            )
        }
    }
}

type Result<T> = core::result::Result<T, FaSEALError>;

fn private_key_arg() -> Arg {
    Arg::new("private key")
        .help("Path to your private key")
        .long("private")
        .short('k')
        .value_parser(value_parser!(PathBuf))
}

fn output_arg() -> Arg {
    Arg::new("output")
        .help("Output file path")
        .long("output")
        .short('o')
        .value_parser(value_parser!(PathBuf))
}

fn encrypted_archive_arg() -> Arg {
    Arg::new("archive")
        .help("Encrypted archive path")
        .value_parser(value_parser!(PathBuf))
        .required(true)
}

fn argon2_params_arg() -> [Arg; 3] {
    [
        Arg::new("cost_m")
            .help(format!(
                "Memory usage in kiB for Argon2 (default: {})",
                Argon2Params::DEFAULT_COST_M
            ))
            .short('m')
            .value_parser(value_parser!(usize)),
        Arg::new("cost_p")
            .help(format!(
                "Parallelism cost for Argon2 (default: {})",
                Argon2Params::DEFAULT_COST_P
                ))
            .short('p')
            .value_parser(value_parser!(usize)),
        Arg::new("cost_t")
            .help(format!(
                "Number of iterations for Argon2 (default: {})",
                Argon2Params::DEFAULT_COST_T
            ))
            .short('t')
            .value_parser(value_parser!(usize))
    ]
}

fn main() {
    let mut cmd = Command::new("faseal")
        .version(FASEAL_VERSION)
        .about(format!(
            "FaSEAL: simple tool for encrypted archives (version {FASEAL_VERSION})\n\
            Copyright (C) 2025 A. Russon"))
        .subcommand(
            Command::new("create")
                .about("Create a new encrypted archive")
                .arg(private_key_arg())
                .arg(
                    Arg::new("public keys")
                        .help("Public key of a recipient")
                        .long("public")
                        .short('p')
                        .value_parser(value_parser!(PathBuf))
                        .action(ArgAction::Append)
                )
                .arg(output_arg().required(true))
                .arg(
                    Arg::new("compression")
                        .help(format!(
                            "Compression level (0-11) (default: {DEFAULT_COMPRESSION_LEVEL})"
                        ))
                        .long("compression")
                        .short('q')
                        .value_parser(value_parser!(u32))
                )
                .arg(
                    Arg::new("files")
                        .help("Files and folder to add to the archive")
                        .value_parser(value_parser!(PathBuf))
                        .action(ArgAction::Append)
                )
        )
        .subcommand(
            Command::new("extract")
                .about("Extract an encrypted archive")
                .arg(private_key_arg())
                .arg(output_arg())
                .arg(encrypted_archive_arg())
        )
        .subcommand(
            Command::new("list")
                .about("List recipients and files of an encrypted archive")
                .arg(private_key_arg())
                .arg(encrypted_archive_arg())
        )
        .subcommand(
            Command::new("keygen")
                .about("Generate a key pair")
                .arg(
                    Arg::new("name")
                        .help("Identity of the owner")
                        .long("name")
                        .short('n')
                        .required(true)
                )
                .arg(
                    Arg::new("contact")
                        .help("Contact of the owner (e.g., email)")
                        .long("contact")
                        .short('c')
                        .default_value("")
                )
                .arg(
                    Arg::new("comment")
                        .help("Comment")
                        .long("comment")
                        .default_value("")
                )
                .args(argon2_params_arg())
        )
        .subcommand(
            Command::new("passwd")
                .about("Change private key password")
                .arg(private_key_arg())
                .args(argon2_params_arg())
        )
        .subcommand(
            Command::new("keyinfo")
            .about("Dump info of a private/public key")
            .arg(private_key_arg())
            .arg(
                Arg::new("public key")
                    .help("Public key")
                    .long("public")
                    .short('p')
                    .value_parser(value_parser!(PathBuf))
            )
            .group(
                ArgGroup::new("key")
                    .args(["private key", "public key"])
                    .required(true)
                    .multiple(false)
                )
            .arg(
                Arg::new("dump")
                    .help("Dump public keys")
                    .long("dump")
                    .short('d')
                    .action(ArgAction::SetTrue)
            )
    );

    let help = cmd.render_long_help();
    let mut matches = cmd.get_matches();

    // read configuration file
    let mut config = match Config::load_config_file() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("[!] {err}");
            match Config::new_with_dir_path() {
                Ok(config) => config,
                Err(err) => {
                    eprintln!("[!] {err} (using current path for private and public paths)");
                    Config::new()
                }
            }
        }
    };

    if let Some((cmd_name, mut matches)) = matches.remove_subcommand() {
        let res = if cmd_name.eq("create") {
            create_archive(&mut matches, &config)
        }
        else if cmd_name.eq("extract") {
            extract_archive(&mut matches, &config)
        }
        else if cmd_name.eq("list") {
            list_archive(&mut matches, &config)
        }
        else if cmd_name.eq("keygen") {
            keygen(&matches, &mut config)
        }
        else if cmd_name.eq("passwd") {
            change_password(&mut matches, &config)
        }
        else {
            // only "key" remains
            info_key(&matches)
        };

        if let Err(err) = res {
            eprintln!("[!] {err}");
        }
    }
    else {
        eprintln!("{}", &help.ansi());
    }
}

fn get_password() -> Result<SecretString> {
    Ok(SecretString::from(prompt_password("Enter password to decrypt your private key: ")?))
}

fn get_private_id(matches: &mut ArgMatches, config: &Config) -> Result<(IdentityPrv, PathBuf)> {
    let private_id_path = match matches.remove_one::<PathBuf>("private key") {
        Some(path) => {
            match path.is_file() {
                true => path,
                false => return Err(FaSEALError::FileNotFound(path))
            }
        },
        None => {
            match config.main_private_id_path() {
                Some(path) => {
                    eprintln!("Using private key: {}", path.display());
                    path.to_path_buf()
                },
                None => return Err(FaSEALError::CliError("no private key provided or available"))
            }
        }
    };
    let password = get_password()?;
    let private_id = IdentityPrv::load_from_file(&password, &private_id_path)?;
    Ok((private_id, private_id_path))
}

fn create_archive(matches: &mut ArgMatches, config: &Config) -> Result<()> {
    // get compression level
    let compression_level = match matches.get_one::<u32>("compression") {
        Some(level) if (0..=11).contains(level) => *level,
        Some(level) if !(0..=11).contains(level) => {
            return Err(FaSEALError::CliError("bad compression level (0-11 expected)"));
        },
        _ => config.compression_level()
    };
    
    // get output path (required argument)
    let output = matches.remove_one::<PathBuf>("output").unwrap();
    if output.exists() {
        return Err(FaSEALError::FileAlreadyExists(output.to_path_buf()));
    }

    // get public identities
    let public_ids: Vec<IdentityPub> = match matches.get_many::<PathBuf>("public keys") {
        Some(v) => {
            let mut public_ids = Vec::<IdentityPub>::with_capacity(v.len());
            for path in v {
                if !path.is_file() {
                    return Err(FaSEALError::FileNotFound(path.to_path_buf()));
                }
                public_ids.push(IdentityPub::load_from_file(path)?);
            }
            public_ids
        },     
        None => vec![]
    };

    // get files and folders to add to the archive
    let files_path: Vec<PathBuf> = match matches.remove_many::<PathBuf>("files") {
        Some(files) => files.collect(),
        None => vec![]
    };
    for path in files_path.iter() {
        if !path.exists() {
            return Err(FaSEALError::FileOrDirNotFound(path.to_path_buf()));
        }
    }

    let (private_id, _) = get_private_id(matches, config)?;

    faseal_core::new_archive(
        &private_id,
        &public_ids,
        files_path.as_slice(),
        &output,
        compression_level
    )?;
    Ok(())
}

fn extract_archive(matches: &mut ArgMatches, config: &Config) -> Result<()> {
    // get private identity
    let (private_id, _) = get_private_id(matches, config)?;

    // get archive path (required argument)
    let path = matches.get_one::<PathBuf>("archive").unwrap();
    if !path.is_file() {
        return Err(FaSEALError::FileNotFound(path.to_path_buf()));
    }
    let mut archive = faseal_core::open_archive(&private_id, path)?;

    // get output path
    let output = match matches.get_one::<PathBuf>("output") {
        Some(output) => output.clone(),
        None => {
            let mut output_default = PathBuf::from(path);
            _ = output_default.set_extension("d");
            output_default
        }
    };

    if !output.exists() {
        std::fs::create_dir(&output)
            .map_err(|e| FaSEALError::DirCannotCreate(output.to_path_buf(), e))?;
    }

    archive.extract_to(&output)?;
    Ok(())
}

fn list_archive(matches: &mut ArgMatches, config: &Config) -> Result<()> {
    // get private identity
    let (private_id, _) = get_private_id(matches, config)?;

    // get archive path (required argument, cannot panic)
    let path = matches.get_one::<PathBuf>("archive").unwrap();
    let archive = faseal_core::open_archive(&private_id, path)?;

    print_recipient_names(archive.public_keys());
    print_files_metadata(archive.metadata_files());
    Ok(())
}

fn print_files_metadata(metadata: &[FileNode]) {
    println!("List of files:");
    print_files_metadata_rec(metadata, 0);
}

fn format_size(size: usize) -> String {
    if size < 10000 {
        format!("{size} B")
    }
    else if size < 10000 * 1024 {
        format!("{} kiB", size >> 10)
    }
    else if size < 10000 * 1024 * 1024 {
        format!("{} MiB", size >> 20)
    }
    else {
        format!("{} GiB", size >> 30)
    }
}

fn print_files_metadata_rec(metadata: &[FileNode], indent: usize) {
    for node in metadata {
        print!("{:width$}└──", " ", width = indent);
        match node.is_dir() {
            true => {
                println!("{}", node.name());
                // unwrap cannot panic since node is a FileNode::Dir
                print_files_metadata_rec(node.get_folder_list().unwrap(), indent + 4);
            },
            false => {
                // unwrap cannot panic node is a FileNode::File
                println!("{} ({})", node.name(), format_size(node.size().unwrap()))
            }
        }
    }
}

fn print_recipient_names(public_keys: &[IdentityPub]) {
    // at least the public key of the creator is present since the archive is opened
    let creator = &public_keys[0];
    if creator.contact().is_empty() {
        println!("Creator: {} [{}]", creator.name(), creator.uuid());
    }
    else {
        println!("Creator: {} [{}] ({})", creator.name(), creator.uuid(), creator.contact());
    }

    match public_keys.len() {
        1 => println!("No recipients."),
        2 => {
            let recipient = &public_keys[1];
            if recipient.contact().is_empty() {
                println!("Recipient: {} [{}]", recipient.name(), recipient.uuid());
            }
            else {
                println!(
                    "Recipient: {} [{}] ({})",
                    recipient.name(),
                    recipient.uuid(),
                    recipient.contact()
                );
            }
        },
        _ => {
            println!("Recipients:");
            for identity in public_keys[1..].iter() {
                if identity.contact().is_empty() {
                    println!("  - {} [{}]", identity.name(), identity.uuid());
                }
                else {
                    println!(
                        "  - {} [{}] ({})",
                        identity.name(),
                        identity.uuid(),
                        identity.contact());
                }
            }
        }
    }
}

fn keygen(matches: &ArgMatches, config: &mut Config) -> Result<()> {
    // "name" is a required argument
    let name = matches.get_one::<String>("name").unwrap();
    
    // "contact" defaults to empty string if not present
    let contact = matches.get_one::<String>("contact").unwrap();

    // "comment" defaults to empty string if not present
    let comment = matches.get_one::<String>("comment").unwrap();

    // get password
    let password = SecretString::from(prompt_password("Password: ")?);
    let password_confirm = SecretString::from(prompt_password("Confirm password: ")?);

    // get Argon2id parameters
    let cost_m = matches.get_one::<usize>("cost_m")
        .map_or_else(|| Argon2Params::DEFAULT_COST_M, |v| *v);

    let cost_p = matches.get_one::<usize>("cost_p")
        .map_or_else(|| Argon2Params::DEFAULT_COST_P, |v| *v);

    let cost_t = matches.get_one::<usize>("cost_t")
        .map_or_else(|| Argon2Params::DEFAULT_COST_T, |v| *v);
    let params = Argon2Params::new(cost_m, cost_p, cost_t);

    // make default?
    let make_default = {
        let mut input = String::new();
        print!("Make this the default private key? [y/N] ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut input)?;
        if let Some(&c) = input.as_bytes().first() {
            c | 0x20 == b'y'
        }
        else {
            false
        }
    };

    // create the private identity and save into files
    faseal_core::keygen::<Kem, Sig>(
        name,
        contact,
        comment,
        &password,
        &password_confirm,
        params,
        config,
        make_default
    )?;

    Ok(())
}

fn change_password(matches: &mut ArgMatches, config: &Config) -> Result<()> {
    // get private identity
    let (mut private_id, private_id_path) = get_private_id(matches, config)?;

    // ask new password
    let new_password = SecretString::from(prompt_password("New password: ")?);
    let new_password_confirm = SecretString::from(
        prompt_password("Confirm new password: ")?
    );

    // get Argon2 parameters
    let cost_m = matches.get_one::<usize>("cost_m")
        .map_or_else(|| Argon2Params::DEFAULT_COST_M, |v| *v);

    let cost_p = matches.get_one::<usize>("cost_p")
        .map_or_else(|| Argon2Params::DEFAULT_COST_P, |v| *v);

    let cost_t = matches.get_one::<usize>("cost_t")
        .map_or_else(|| Argon2Params::DEFAULT_COST_T, |v| *v);
    let params = Argon2Params::new(cost_m, cost_p, cost_t);

    faseal_core::change_password(
        &mut private_id,
        &private_id_path,
        &new_password,
        &new_password_confirm,
        params,
        config
    )?;

    Ok(())
}

fn info_key(matches: &ArgMatches) -> Result<()> {
    let dump = matches.get_flag("dump");

    if let Some(path) = matches.get_one::<PathBuf>("private key") {
        if !path.is_file() {
            return Err(FaSEALError::FileNotFound(path.to_path_buf()));
        }
        let password = get_password()?;
        let private_id = IdentityPrv::load_from_file(&password, path)?;
        let public_id = private_id.public_ref();
        print_public_id(public_id, dump);
        println!("{}", private_id.params());
    }
    else {
        // "private key" and "public key" are mutually exclusive
        let path = matches.get_one::<PathBuf>("public key").unwrap();
        if !path.is_file() {
            return Err(FaSEALError::FileNotFound(path.to_path_buf()));
        }
        let public_id = IdentityPub::load_from_file(path)?;
        print_public_id(&public_id, dump);
    }
    Ok(())
}

fn print_public_id(public_id: &IdentityPub, dump: bool) {
    if public_id.contact().is_empty() {
        println!("Identity: {} [{}]", public_id.name(), public_id.uuid());
    }
    else {
        println!("Identity: {} [{}] ({})", public_id.name(), public_id.uuid(), public_id.contact());
    }
    if !public_id.comment().is_empty() {
        println!("Comment: {}", public_id.comment());
    }

    if dump {
        println!("Verifying key: {}", hex::encode(public_id.verifying_key().as_ref()));
        println!("Encapsulation key: {}", hex::encode(public_id.encaps_key().as_ref()));
    }
}
