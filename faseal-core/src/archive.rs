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

use std::{
    io::{
        BufReader,
        BufWriter,
        Read,
        Write
    },
    fs::{
        File,
        read_dir
    },
    path::{
        Path,
        PathBuf
    }
};

use rand::RngCore;
use zeroize::{
    Zeroize,
    ZeroizeOnDrop
};

use faseal_crypto::{
    aead::{
        ChaCha20Poly1305,
        KEY_LENGTH,
        TAG_LENGTH
    },
    array::ZeroizeArray,
    hashes::sha3::Sha3_512,
    traits::{
        arrayt::{
            AsSlice,
            NewArray
        },
        kemt::KemT,
        sigt::SigT
    }
};

use crate::{
    errors::{
        Error,
        Result
    },
    identities::{
        IdentityPrv,
        IdentityPub,
    },
    utils::read_buf_var,
    MAX_STRING_LENGTH,
    VERSION_FORMAT
};

const DEFAULT_MAX_RECIPIENTS: usize = 256;
pub const DEFAULT_COMPRESSION_LEVEL: u32 = 9;
const BROTLI_BUFFER_SIZE: usize = 4096;
const BROTLI_LG_WIN: u32 = 22;
const UNCOMPRESSED_BLOCK_SIZE: usize = 1024 * 1024;

pub(crate) const NONCE_NULL: &[u8; 12] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const NONCE_LEN_ZONE:        &[u8; 12] = NONCE_NULL;
const NONCE_PUBKEY_ZONE:     &[u8; 12] = &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const NONCE_FILENAME_ZONE:   &[u8; 12] = &[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const NONCE_FILE_ZONE:       &[u8; 12] = &[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

const MAGIC_ARCHIVE: &[u8; 10] = b"FaSEAL/arc";
const VERSION_ARCHIVE: &[u8; 4] = VERSION_FORMAT;

const fn default_max_encaps_zone_len<KEM: KemT>() -> usize {
    DEFAULT_MAX_RECIPIENTS * (KEM::CIPHERTEXT_LEN + KEY_LENGTH + TAG_LENGTH) + 8
}

enum FileFlag {
    File = 0,
    Folder = 1,
    EndFolder = 253,
    EndArchive = 254,
    Unknown = 255
}

impl From<u8> for FileFlag {
    fn from(value: u8) -> Self {
        match value {
            0   => FileFlag::File,
            1   => FileFlag::Folder,
            253 => FileFlag::EndFolder,
            254 => FileFlag::EndArchive,
            _   => FileFlag::Unknown
        }
    }
}

fn compress_file(
    reader: &mut File,
    writer: &mut Vec<u8>,
    len: usize,
    compression_level: u32
) -> Result<Vec<u32>> {
    let indexes_len = len.div_ceil(UNCOMPRESSED_BLOCK_SIZE);
    let mut compressed_chunks_sizes = vec![0u32; indexes_len];

    for compressed_chunk_size in compressed_chunks_sizes.iter_mut() {
        let mut compress = brotli::CompressorReader::new(
            reader.take(UNCOMPRESSED_BLOCK_SIZE as u64),
            BROTLI_BUFFER_SIZE,
            compression_level,
            BROTLI_LG_WIN
        );
        *compressed_chunk_size = compress.read_to_end(writer)? as u32;
    }

    Ok(compressed_chunks_sizes)
}

fn add_file_or_dir(
    list_filenames: &mut BufWriter<Vec<u8>>,
    compressed_files: &mut Vec<u8>,
    path: &Path,
    compression_level: u32
) -> Result<()> {
    let name = path.file_name().unwrap().to_string_lossy();
    if path.is_file() {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        let position = compressed_files.len();
        let compressed_chunks_sizes = compress_file(
            &mut file,
            compressed_files,
            len as usize,
            compression_level
        )?;
        let len_compressed = compressed_files.len() - position;

        list_filenames.write_all(&[FileFlag::File as u8])?;
        list_filenames.write_all(&(name.len() as u64).to_le_bytes())?;
        list_filenames.write_all(name.as_bytes())?;
        list_filenames.write_all(&(position as u64).to_le_bytes())?;
        list_filenames.write_all(&(len_compressed as u64).to_le_bytes())?;
        list_filenames.write_all(&len.to_le_bytes())?;
        list_filenames.write_all(&(compressed_chunks_sizes.len() as u64).to_le_bytes())?;
        for chunk_size in compressed_chunks_sizes.iter() {
            list_filenames.write_all(&(chunk_size.to_le_bytes()))?;
        }
        Ok(())
    }
    else if path.is_dir() {
        list_filenames.write_all(&[FileFlag::Folder as u8])?;
        list_filenames.write_all(&(name.len() as u64).to_le_bytes())?;
        list_filenames.write_all(name.as_bytes())?;

        let mut paths = read_dir(path)?
            .map(|res| res.map(|e| e.path()))
            .collect::<core::result::Result<Vec<_>, std::io::Error>>()?;
        paths.sort();

        for path in paths.iter() {
            add_file_or_dir(
                list_filenames,
                compressed_files,
                path,
                compression_level
            )?;
        }
        list_filenames.write_all(&[FileFlag::EndFolder as u8])?;
        Ok(())
    }
    else {
        Err(Error::FileNotFound(path.to_path_buf()))
    }
}

fn verify_duplicate(paths: &[PathBuf]) -> Result<()> {
    let mut file_names = Vec::new();
    for path in paths {
        if let Some(file_name) = path.file_name() {
            if file_names.contains(&file_name) {
                return Err(Error::Duplicate(String::from(file_name.to_string_lossy())));
            }
            file_names.push(file_name);
        }
    }
    Ok(())
}

pub fn new_archive<KEM: KemT, SIG: SigT>(
    private_id: &IdentityPrv<KEM, SIG>,
    public_ids: &[IdentityPub<KEM, SIG>],
    paths: &[PathBuf],
    fname: &Path,
    compression_level: u32
) -> Result<()> {
    // 1. verify if two files with the same name are present at the root of the archive
    verify_duplicate(paths)?;

    // 2. generate symmetric key and a secret random
    let mut master_key = ZeroizeArray::<KEY_LENGTH>::new();
    rand::rng().fill_bytes(master_key.as_mut());
    let mut secret_random = ZeroizeArray::<32>::new();
    rand::rng().fill_bytes(secret_random.as_mut());

    // 3. get an encapsulated secret and encrypt the secret key for each recipient
    // 3.1. assemble all encaps keys
    let mut encaps_keys = Vec::<&KEM::EncapsKey>::new();
    encaps_keys.push(private_id.public_ref().encaps_key());
    for public_id in public_ids {
        encaps_keys.push(public_id.encaps_key());
    }

    // 3.2. number of encapsulations
    let mut encapsulated_zone = BufWriter::new(Vec::<u8>::new());
    encapsulated_zone.write_all(&(encaps_keys.len() as u64).to_le_bytes())?;

    // 3.3. encapsulate and encrypt the master key
    for encaps_key in encaps_keys {
        let (recipient_key, ciphertext) = KEM::encaps(encaps_key);
        // each key has a single use, so nonce is null
        let (encrypted_key, tag) = ChaCha20Poly1305::new(recipient_key.as_ref(), NONCE_NULL)
            .encrypt(b"encaps", master_key.as_ref());
        encapsulated_zone.write_all(ciphertext.as_slice())?;
        encapsulated_zone.write_all(&encrypted_key)?;
        encapsulated_zone.write_all(&tag)?;
    }

    let mut encapsulated_zone = encapsulated_zone.into_inner().map_err(|e| e.into_error())?;
    
    // 4. generate authentication data as the hash of the encapsulation zone
    let aad = Sha3_512::hash(&[&encapsulated_zone]);

    // 5. add public keys in the public key zone
    let mut pubkey_zone = BufWriter::new(Vec::<u8>::new());
    
    // 5.1. add the creator's public key
    let dump = private_id.public_ref().dump()?;
    pubkey_zone.write_all(&(dump.len() as u64).to_le_bytes())?;
    pubkey_zone.write_all(&dump)?;

    // 5.2. add recipient public keys
    for public_id in public_ids {
        let dump = public_id.dump()?;
        pubkey_zone.write_all(&(dump.len() as u64).to_le_bytes())?;
        pubkey_zone.write_all(&dump)?;
    }
    let mut pubkey_zone = pubkey_zone.into_inner().map_err(|e| e.into_error())?;

    // 5.3. encrypt public keys
    let pubkey_zone_tag = ChaCha20Poly1305::new(master_key.as_ref(), NONCE_PUBKEY_ZONE)
        .encrypt_in_place(&aad, &mut pubkey_zone);

    // 6/7. prepare file name zone and file zone
    let mut filename_zone = BufWriter::new(Vec::<u8>::new());
    let mut file_zone = Vec::<u8>::new();
    for path in paths {
        add_file_or_dir(&mut filename_zone, &mut file_zone, path, compression_level)?;
    }
    filename_zone.write_all(&[FileFlag::EndArchive as u8])?;
    let mut filename_zone = filename_zone.into_inner().map_err(|e| e.into_error())?;
    let filename_zone_tag = ChaCha20Poly1305::new(master_key.as_ref(), NONCE_FILENAME_ZONE)
        .encrypt_in_place(&aad, &mut filename_zone);
    let file_zone_tag = ChaCha20Poly1305::new(master_key.as_ref(), NONCE_FILE_ZONE)
        .encrypt_in_place(&aad, &mut file_zone);

    // 8. Length zone, with a secret random
    let mut len_zone = [0u8; 56];
    len_zone[0..8].copy_from_slice(&(pubkey_zone.len() as u64).to_le_bytes());
    len_zone[8..16].copy_from_slice(&(filename_zone.len() as u64).to_le_bytes());
    len_zone[16..24].copy_from_slice(&(file_zone.len() as u64).to_le_bytes());
    len_zone[24..56].copy_from_slice(secret_random.as_ref());

    let len_zone_tag = ChaCha20Poly1305::new(master_key.as_ref(), NONCE_LEN_ZONE)
        .encrypt_in_place(&aad, &mut len_zone);

    // 9/10. create file and signature
    let mut writer = BufWriter::new(
        File::create(fname)
            .map_err(|_| Error::CannotCreateFile(fname.to_path_buf()))?
    );
    let mut signer = Sha3_512::init();

    macro_rules! write_and_sign {
        ($buf:expr) => {
            writer.write_all($buf)?;
            signer.update($buf);
        };
    }

    // magic, format version, and asymmetric algorithms
    write_and_sign!(MAGIC_ARCHIVE);
    write_and_sign!(VERSION_ARCHIVE);

    // encapsulated zone
    let encapsulated_zone_len = (encapsulated_zone.len() as u64).to_le_bytes();
    write_and_sign!(&encapsulated_zone_len);
    write_and_sign!(&encapsulated_zone);
    encapsulated_zone.zeroize();

    // encrypted lengths
    write_and_sign!(&len_zone);
    write_and_sign!(&len_zone_tag);
    len_zone.zeroize();

    // encrypted public keys
    write_and_sign!(&pubkey_zone);
    write_and_sign!(&pubkey_zone_tag);
    pubkey_zone.zeroize();

    // encrypted file list
    write_and_sign!(&filename_zone);
    write_and_sign!(&filename_zone_tag);
    filename_zone.zeroize();

    // encrypted files
    write_and_sign!(&file_zone);
    write_and_sign!(&file_zone_tag);
    file_zone.zeroize();

    // signature
    // secret random in the signature (stored as encrypted in the length zone)
    // so a signature can only be verified after decryption and avoid leaking
    // the identity of the creator
    signer.update(secret_random.as_ref());
    let msg = signer.finalize();
    let signature = SIG::sign(private_id.signing_key(), &msg);
    writer.write_all(signature.as_slice())?;

    Ok(())
}

#[derive(Zeroize)]
pub struct FileInfo {
    name: String,
    position: usize,
    len: usize,
    len_compressed: usize,
    chunks_sizes: Vec<u32>
}

pub struct DirInfo {
    name: String,
    list: Vec<FileNode>
}

pub enum FileNode {
    File(FileInfo),
    Dir(DirInfo)
}

impl FileNode {
    pub fn name(&self) -> &str {
        match self {
            Self::Dir(info) => &info.name,
            Self::File(info) => &info.name,
        }
    }

    pub fn is_dir(&self) -> bool {
        match self {
            Self::Dir(_) => true,
            Self::File(_) => false,
        }
    }

    pub fn get_folder_list(&self) -> Option<&Vec<FileNode>> {
        match self {
            Self::Dir(info) => Some(&info.list),
            Self::File(_) => None,
        }
    }

    pub fn size(&self) -> Option<usize> {
        match self {
            Self::File(info) => Some(info.len),
            Self::Dir(_) => None
        }
    }
}

impl Zeroize for FileNode {
    fn zeroize(&mut self) {
        match self {
            Self::File(info) => info.zeroize(),
            Self::Dir(info) => info.name.zeroize()
        }
    }
}

impl ZeroizeOnDrop for FileNode {}

fn read_file_or_dir(
    reader: &mut BufReader<&[u8]>,
    list_filenames: &mut Vec<FileNode>,
    current_length: &mut usize
) -> Result<FileFlag> {
    let mut flag = [0u8; 1];
    reader.read_exact(&mut flag)?;
    match FileFlag::from(flag[0]) {
        FileFlag::File => {
            let mut buf_len = [0u8; 8];

            // file name
            let buf = read_buf_var(reader, &mut buf_len, MAX_STRING_LENGTH)?;
            let name = String::from_utf8(buf)?;
            
            // file position (must agree with current length)
            reader.read_exact(&mut buf_len)?;
            let position = u64::from_le_bytes(buf_len) as usize;
            if position != *current_length {
                return Err(Error::ArchiveCorrupted);
            }

            // file compressed length
            reader.read_exact(&mut buf_len)?;
            let len_compressed = u64::from_le_bytes(buf_len) as usize;
            *current_length += len_compressed;

            // file length, chunk sizes
            reader.read_exact(&mut buf_len)?;
            let len_uncompressed = u64::from_le_bytes(buf_len) as usize;
            reader.read_exact(&mut buf_len)?;
            let chunks_sizes_len = u64::from_le_bytes(buf_len) as usize;
            let mut chunks_sizes = vec![0u32; chunks_sizes_len];
            for size in chunks_sizes.iter_mut() {
                let mut len = [0u8; 4];
                reader.read_exact(&mut len)?;
                *size = u32::from_le_bytes(len);
            }

            list_filenames.push(
                FileNode::File(
                    FileInfo {
                        name,
                        position,
                        len: len_uncompressed,
                        len_compressed,
                        chunks_sizes
                    }
                )
            );
            Ok(FileFlag::File)
        },

        FileFlag::Folder => {
            let mut buf_len = [0u8; 8];
            let buf = read_buf_var(reader, &mut buf_len, MAX_STRING_LENGTH)?;
            let name = String::from_utf8(buf)?;
            let mut sub_list_filenames = Vec::<FileNode>::new();
            loop {
                if let FileFlag::EndFolder = read_file_or_dir(
                    reader,
                    &mut sub_list_filenames,
                    current_length
                )? {
                    break;
                }
            }
            list_filenames.push(
                FileNode::Dir(
                    DirInfo {
                        name,
                        list: sub_list_filenames
                    }
                )
            );
            Ok(FileFlag::Folder)
        },

        FileFlag::EndFolder => Ok(FileFlag::EndFolder),
        
        FileFlag::EndArchive => Ok(FileFlag::EndArchive),

        FileFlag::Unknown => Err(Error::ArchiveCorrupted)
    }
} 

fn get_masterkey<KEM: KemT, SIG: SigT>(
    private_id: &IdentityPrv<KEM, SIG>,
    encapsulated_zone: &[u8],
    master_key: &mut [u8; KEY_LENGTH]
) -> Result<(usize, usize)> {    
    let mut reader = BufReader::new(encapsulated_zone);

    // number of public identities
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    let num_public_identities = u64::from_le_bytes(buf) as usize;

    // verify that the number of bytes remaining in the encapsulated zone
    // is consistent with the number of public identities
    let expected_len = num_public_identities * (KEM::CIPHERTEXT_LEN + KEY_LENGTH + TAG_LENGTH) + 8;
    if expected_len != encapsulated_zone.len() {
        return Err(Error::ArchiveCorrupted);
    }

    let mut ciphertext = KEM::Ciphertext::new();
    let mut tag = [0u8; TAG_LENGTH];
    for position in 0..num_public_identities {
        reader.read_exact(ciphertext.as_mut_slice())?;
        let key = KEM::decaps(private_id.decaps_key(), &ciphertext);
        let aead = ChaCha20Poly1305::new(key.as_ref(), NONCE_NULL);
        reader.read_exact(master_key)?;
        reader.read_exact(&mut tag)?;

        if aead.decrypt_in_place(b"encaps", master_key, &tag).is_ok() {
            return Ok((position, num_public_identities));
        }
    }

    Err(Error::Archive("not a recipient"))
}

pub struct OpenedArchive<KEM: KemT, SIG: SigT> {
    public_identities: Vec<IdentityPub<KEM, SIG>>,
    list_files: Vec<FileNode>,
    encrypted_files: Vec<u8>,
    encrypted_files_tag: [u8; TAG_LENGTH],
    auth_data: [u8; Sha3_512::HASH_LEN],
    master_key: [u8; KEY_LENGTH],
}

pub fn open_archive<KEM: KemT, SIG: SigT>(
    private_id: &IdentityPrv<KEM, SIG>,
    fname: &Path
) -> Result<OpenedArchive<KEM, SIG>> {
    let file = File::open(fname)?;
    let file_length = file.metadata()?.len() as usize;
    let mut reader = BufReader::new(file);
    let mut verifier = Sha3_512::init();

    macro_rules! read_and_verify {
        ($buf:expr) => {
            reader.read_exact(&mut $buf)?;
            verifier.update(&$buf);
        };
    }

    // 1. verify magic and version
    let mut magic = [0u8; MAGIC_ARCHIVE.len()];
    read_and_verify!(magic);
    if !magic.eq(MAGIC_ARCHIVE) {
        return Err(Error::Archive("bad magic number"));
    }

    let mut version = [0u8; VERSION_ARCHIVE.len()];
    read_and_verify!(version);
    if !version.eq(VERSION_ARCHIVE) {
        return Err(Error::Archive("unsupported archive version"));
    }

    // 2. read encapsulated zone
    let mut len = [0u8; 8];
    read_and_verify!(len);
    let encaps_zone_len = u64::from_le_bytes(len) as usize;
    if encaps_zone_len > default_max_encaps_zone_len::<KEM>() {
        return Err(Error::Archive("too many recipients"));
    }
    
    let mut encapsulated_zone = vec![0u8; encaps_zone_len];
    read_and_verify!(encapsulated_zone);
    let aad = Sha3_512::hash(&[&encapsulated_zone]);
    
    // 3. try decaps for all encapsulated keys (abort if nothing found)
    let mut master_key = ZeroizeArray::<KEY_LENGTH>::new();
    let (decaps_position, num_public_identities) = get_masterkey(
        private_id, &encapsulated_zone, master_key.as_mut()
    )?;

    // 4. decrypt length zone
    let mut len_zone = [0u8; 56];
    let mut len_zone_tag = [0u8; TAG_LENGTH];
    read_and_verify!(len_zone.as_mut());
    read_and_verify!(len_zone_tag);

    ChaCha20Poly1305::new(master_key.as_ref(), NONCE_LEN_ZONE)
        .decrypt_in_place(&aad, &mut len_zone, &len_zone_tag)?;

    let pubkey_zone_len = u64::from_le_bytes(len_zone[0..8].try_into().unwrap()) as usize;
    let listfiles_zone_len = u64::from_le_bytes(len_zone[8..16].try_into().unwrap()) as usize;
    let files_zone_len = u64::from_le_bytes(len_zone[16..24].try_into().unwrap()) as usize;
    let mut secret_random = [0u8; 32];
    secret_random.copy_from_slice(&len_zone[24..56]);
    len_zone.zeroize();

    // verify that the lengths are consistent with the file length
    let bytes_read = MAGIC_ARCHIVE.len() + VERSION_ARCHIVE.len()
        + 8 + encaps_zone_len // encapsulated zone and its length
        + 56 + TAG_LENGTH;    // length zone and its authentication tag

    // addition with a check on overflow to prevent malformed archives
    // where the total is correct with overflow, but will cause a panic
    // on memory allocation of each zone
    let values = [
        pubkey_zone_len, listfiles_zone_len, files_zone_len, 3 * TAG_LENGTH + SIG::SIGNATURE_LEN
    ];
    match values.iter().try_fold(bytes_read, |acc, &x| acc.checked_add(x)) {
        Some(total_length) if total_length == file_length => (),
        _ => return Err(Error::ArchiveCorrupted)
    }

    // 5. get encrypted public keys and decrypt
    let mut pubkey_zone = vec![0u8; pubkey_zone_len];
    let mut pubkey_zone_tag = [0u8; TAG_LENGTH];
    read_and_verify!(pubkey_zone);
    read_and_verify!(pubkey_zone_tag);
    
    ChaCha20Poly1305::new(master_key.as_ref(), NONCE_PUBKEY_ZONE)
        .decrypt_in_place(&aad, &mut pubkey_zone, &pubkey_zone_tag)?;

    let mut offset = 0;
    let mut public_identities = Vec::<IdentityPub<KEM, SIG>>::with_capacity(num_public_identities);

    for _ in 0..num_public_identities {
        let Some(buf) = pubkey_zone.get(offset..offset + 8) else {
            return Err(Error::ArchiveCorrupted);
        };
        let len = u64::from_le_bytes(buf.try_into().unwrap()) as usize;
        let Some(dump) = pubkey_zone.get(offset + 8..offset + 8 + len) else {
            return Err(Error::ArchiveCorrupted);
        };
        public_identities.push(IdentityPub::<KEM, SIG>::load_from_dump(dump)?);
        offset += 8 + len;
    }
    // verify the public id is in the same position as the encapsulation    
    if !public_identities
        .get(decaps_position)
        .is_some_and(|public_id| public_id == private_id.public_ref())
    {
        return Err(Error::ArchiveCorrupted);
    }
    pubkey_zone.zeroize();
    // verify for extra bytes in the public zone
    if offset != pubkey_zone_len {
        return Err(Error::ArchiveCorrupted);
    }
    
    // 6. get file list and decrypt
    let mut filename_zone = vec![0u8; listfiles_zone_len];
    let mut filename_zone_tag = [0u8; TAG_LENGTH];
    read_and_verify!(filename_zone);
    read_and_verify!(filename_zone_tag);

    ChaCha20Poly1305::new(master_key.as_ref(), NONCE_FILENAME_ZONE)
        .decrypt_in_place(&aad, &mut filename_zone, &filename_zone_tag)?;
    
    // parsing list of files
    let mut list_files = Vec::<FileNode>::new();
    let mut buf = BufReader::new(filename_zone.as_slice());
    let mut expected_file_zone_len = 0;
    loop {
        if let FileFlag::EndArchive = read_file_or_dir(
            &mut buf,
            &mut list_files,
            &mut expected_file_zone_len
        )? {
            break;
        }
    }
    if buf.read(&mut [0u8])? > 0 || expected_file_zone_len != files_zone_len {
        return Err(Error::ArchiveCorrupted)
    }
    filename_zone.zeroize();

    // 7. get encrypted files (verify tag only)
    let mut encrypted_file_zone = vec![0u8; files_zone_len];
    let mut encrypted_file_zone_tag = [0u8; TAG_LENGTH];
    read_and_verify!(encrypted_file_zone);
    read_and_verify!(encrypted_file_zone_tag);
    
    ChaCha20Poly1305::new(master_key.as_ref(), NONCE_FILE_ZONE)
        .verify_tag(&aad, &encrypted_file_zone, &encrypted_file_zone_tag)?;

    // 8. get signature and verify
    let mut signature = SIG::Signature::new();
    reader.read_exact(signature.as_mut_slice())?;
    // add the secret random in the verification
    verifier.update(&secret_random);
    secret_random.zeroize();
    let msg = verifier.finalize();
    SIG::verify(public_identities[0].verifying_key(), &msg, &signature)?;

    // 9. verify that no extra bytes are appended to the archive
    if reader.read(&mut [0u8])? > 0 {
        return Err(Error::ArchiveCorrupted);
    }

    Ok(
        OpenedArchive {
            public_identities,
            list_files,
            encrypted_files: encrypted_file_zone,
            encrypted_files_tag: encrypted_file_zone_tag,
            auth_data: aad,
            master_key: *master_key.as_ref()
        }
    )
}

fn decompress_file(
    reader: &mut BufReader<&[u8]>,
    writer: &mut File,
    chunk_sizes: &[u32],
    file_len: usize
) -> Result<()> {
    if chunk_sizes.is_empty() {
        return Ok(());
    }

    // large buffer, so it is allocated in heap
    let mut buf = vec![0u8; UNCOMPRESSED_BLOCK_SIZE];
    
    // all but last must fill the whole buffer
    for &size in chunk_sizes.iter().take(chunk_sizes.len() - 1) {
        let mut decompressor = brotli::Decompressor::new(
            reader.take(size as u64),
            BROTLI_BUFFER_SIZE
        );
        decompressor.read_exact(&mut buf)?;
        writer.write_all(&buf)?;
    }

    // last chunk (might not fill whole buffer)
    let mut decompressor = brotli::Decompressor::new(
        // chunk_sizes is not empty, so unwrap is safe
        reader.take(*chunk_sizes.last().unwrap() as u64),
        BROTLI_BUFFER_SIZE
    );
    let len = file_len - UNCOMPRESSED_BLOCK_SIZE * (chunk_sizes.len() - 1);
    decompressor.read_exact(&mut buf[..len])?;
    writer.write_all(&buf[..len])?;

    Ok(())
}

fn write_file_or_dir(
    node: &FileNode,
    path: &Path,
    buffer: &[u8]
) -> Result<()> {
    match node {
        FileNode::Dir(dir_info) => {
            let path = path.join(&dir_info.name);
            std::fs::create_dir(&path)?;
            for node in dir_info.list.iter() {
                write_file_or_dir(node, &path, buffer)?;
            }
        },

        FileNode::File(file_info) => {
            match buffer.get(
                file_info.position..file_info.position + file_info.len_compressed
            ) {
                Some(compressed) => {
                    let path = path.join(&file_info.name);
                    let mut file = File::create(path)?;
                    let mut reader = BufReader::new(compressed);
                    decompress_file(
                        &mut reader,
                        &mut file,
                        &file_info.chunks_sizes,
                        file_info.len
                    )?;
                },
                None => return Err(Error::ArchiveCorrupted),
            }
        }
    }
    Ok(())
}

impl<KEM: KemT, SIG: SigT> OpenedArchive<KEM, SIG> {
    // expects dirname to be a valid destination folder
    pub fn extract_to(&mut self, dirname: &Path) -> Result<()> {
        // 1. Decrypt files
        let mut buffer = ChaCha20Poly1305::new(&self.master_key, NONCE_FILE_ZONE)
            .decrypt(&self.auth_data, &self.encrypted_files, &self.encrypted_files_tag)?;

        // 2. Recurse through the tree:
        //    - Folder:
        //      * create the folder in current path if it does not exist
        //      * update the current path (root is dirname)
        //    - EndFolder:
        //      * remove one level from the current path
        //      * keep track that it does go further back than `dirname`
        //    - File:
        //      * take slice from the buffer using compressed length
        //      * uncompress and verify uncompressed length
        //      * write file in current path
        //    All along, an error should stop the process.
        //    The whole buffer of files must be used by the end.
        for node in self.list_files.iter() {
            write_file_or_dir(node, dirname, &buffer)?;
        }

        // 3. Erase all buffers but keep intact the encrypted buffer.
        buffer.zeroize();

        Ok(())
    }

    pub fn metadata_files(&self) -> &Vec<FileNode> {
        &self.list_files
    }

    pub fn public_keys(&self) -> &Vec<IdentityPub<KEM, SIG>> {
        &self.public_identities
    }
}

impl<KEM: KemT, SIG: SigT> Drop for OpenedArchive<KEM, SIG> {
    fn drop(&mut self) {
        self.encrypted_files.zeroize();
        self.encrypted_files_tag.zeroize();
        self.master_key.zeroize();
        self.list_files.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const BROTLI_Q: u32 = 9;
    use faseal_crypto::{
        kem::MlKem768X25519,
        sig::MlDsa65Ed25519,
        argon2::Argon2Params
    };

    use tempfile::TempDir;

    #[test]
    fn test_read_file() {
        let filenames = hex_literal::hex!("
            00090000000000000066696c65312e7478740000000000000000180000000000
            0000140000000000000001000000000000001800000000090000000000000066
            696c65322e747874180000000000000017000000000000001300000000000000
            010000000000000017000000010700000000000000666f6c6465723100090000
            000000000066696c65332e7478742f0000000000000017000000000000001300
            000000000000010000000000000017000000010700000000000000666f6c6465
            723200090000000000000066696c65342e747874460000000000000017000000
            000000001300000000000000010000000000000017000000fdfdfe
        ");
        // list of file names
        // - file1.txt       
        // - file2.txt       
        // - folder1/file3.txt       
        // - folder1/folder2/file4.txt       

        let mut list = Vec::<FileNode>::new();
        let mut buf = BufReader::new(filenames.as_slice());
        let mut length = 0;
        assert!(matches!(read_file_or_dir(&mut buf, &mut list, &mut length), Ok(FileFlag::File)));
        assert!(matches!(read_file_or_dir(&mut buf, &mut list, &mut length), Ok(FileFlag::File)));
        assert!(matches!(read_file_or_dir(&mut buf, &mut list, &mut length), Ok(FileFlag::Folder)));
        assert!(matches!(
            read_file_or_dir(&mut buf, &mut list, &mut length), 
            Ok(FileFlag::EndArchive))
        );
        assert_eq!(length, 93);
    }

    #[test]
    fn test_read_file_corrupted() {
        let filenames = hex_literal::hex!("
            00090000000000000066696c65312e7478740000000000000000180000000000
            0000140000000000000001000000000000001800000000090000000000000066
            696c65322e747874180000000000000017000000000000001300000000000000
            010000000000000017000000010700000000000000666f6c6465723100090000
            000000000066696c65332e7478742f0000000000000017000000000000001300
            000000000000010000000000000017000000010700000000000000666f6c6465
            723200090000000000000066696c65342e747874450000000000000017000000
            000000001300000000000000010000000000000017000000fdfdfe
        ");
        // position of last file is changed from 70 to 69 compared to previous test

        let mut list = Vec::<FileNode>::new();
        let mut buf = BufReader::new(filenames.as_slice());
        let mut length = 0;
        assert!(matches!(read_file_or_dir(&mut buf, &mut list, &mut length), Ok(FileFlag::File)));
        assert!(matches!(read_file_or_dir(&mut buf, &mut list, &mut length), Ok(FileFlag::File)));
        assert!(
            matches!(read_file_or_dir(&mut buf, &mut list, &mut length),
            Err(Error::ArchiveCorrupted))
        );
    }

    fn test_compare_filenode(list1: &[FileNode], list2: &[FileNode]) -> bool {
        if list1.len() != list2.len() {
            return false;
        }
        for (node1, node2) in list1.iter().zip(list2.iter()) {
            let equal = match node1 {
                FileNode::File(info1) => {
                    if let FileNode::File(info2) = node2 {
                        info1.name == info2.name
                            && info1.position == info2.position
                            && info1.len == info2.len
                            && info1.len_compressed == info2.len_compressed
                            && info1.chunks_sizes == info2.chunks_sizes
                    }
                    else {
                        false
                    }
                },
                FileNode::Dir(info1) => {
                    if let FileNode::Dir(info2) = node2 {
                        info1.name == info2.name
                            && info1.list.len() == info2.list.len()
                            && test_compare_filenode(&info1.list, &info2.list)
                    }
                    else {
                        false
                    }
                }
            };
            if !equal {
                return false;
            }
        }
        true
    }

    #[test]
    fn test_create_archive() {        
        let tmp_dir = TempDir::new().unwrap();
        let tmp_path = tmp_dir.path();
        // create files and folders in temp directory
        let file_paths = [
            "file1.txt",
            "file2.txt",
            "folder1/file3.txt",
            "folder1/file4.txt",
            "folder1/folder2/file1.txt",
            "folder1/folder2/file5.txt",
            "folder1/folder2/file6.txt"
        ];
        std::fs::create_dir_all(tmp_path.join("folder1/folder2/")).unwrap();
        
        for (i, path) in file_paths.iter().enumerate() {
            File::create(tmp_path.join(path)).unwrap()
                .write_all(format!("A simple file {i}").as_bytes()).unwrap();
        }

        // create identities of creator and recipient
        let creator_private_id = IdentityPrv::<MlKem768X25519, MlDsa65Ed25519>::create(
            "user1", "no contact", "no comment", Argon2Params::default()
        ).unwrap();
        let recipient_private_id = IdentityPrv::<MlKem768X25519, MlDsa65Ed25519>::create(
            "user2", "no contact", "no comment", Argon2Params::default()
        ).unwrap();
        let recipient_public_id = recipient_private_id.public();

        // create archive
        let paths = [
            tmp_path.join("file1.txt"),
            tmp_path.join("folder1/file4.txt"),
            tmp_path.join("folder1/folder2")
        ];
        let archive_path = tmp_path.join("archive1.sealed");
        new_archive(
            &creator_private_id,
            &[recipient_public_id],
            &paths,
            &archive_path,
            BROTLI_Q
        ).unwrap();

        // open and extract archive
        let archive_creator = open_archive(
            &creator_private_id,
            &archive_path
        ).unwrap();

        let archive_recipient = open_archive(
            &recipient_private_id,
            &archive_path
        ).unwrap();

        // compare archives
        assert_eq!(archive_creator.auth_data, archive_recipient.auth_data);
        assert_eq!(archive_creator.encrypted_files, archive_recipient.encrypted_files);
        assert_eq!(archive_creator.encrypted_files_tag, archive_recipient.encrypted_files_tag);
        assert_eq!(archive_creator.master_key, archive_recipient.master_key);
        assert_eq!(
            archive_creator.public_identities.len(),
            archive_recipient.public_identities.len()
        );
        for (id1, id2) in archive_creator.public_identities.iter()
            .zip(archive_recipient.public_identities.iter())
        {
            assert!(id1.eq(id2));
        }
        assert_eq!(
            archive_creator.list_files.len(),
            archive_recipient.list_files.len()
        );
        assert!(test_compare_filenode(&archive_creator.list_files, &archive_recipient.list_files));
    }

    #[test]
    fn test_create_archive_duplicate() {
        let tmp_dir = TempDir::new().unwrap();

        // create identities of creator
        let creator_private_id = IdentityPrv::<MlKem768X25519, MlDsa65Ed25519>::create(
            "user1", "no contact", "no comment", Argon2Params::default()
        ).unwrap();


        // create archive
        let paths = [
            PathBuf::from("test/files/file1.txt"),
            PathBuf::from("test/files/folder1/folder2/file1.txt")
        ];
        let archive_path = tmp_dir.path().join("archive1.sealed");
        let res = new_archive(
            &creator_private_id,
            &[],
            &paths,
            &archive_path,
            BROTLI_Q
        );
        assert!(res.is_err_and(|e| matches!(e, Error::Duplicate(_))));
    }
}
