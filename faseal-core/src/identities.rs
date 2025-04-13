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
    fs::File,
    io::{
        BufReader,
        BufWriter,
        Read,
        Write
    },
    path::Path
};

use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use faseal_crypto::{
    aead::{
        ChaCha20Poly1305,
        KEY_LENGTH,
        TAG_LENGTH,
    },
    argon2::{Argon2, Argon2Params},
    array::ZeroizeArray,
    hashes::sha3::Sha3_512,
    traits::{
        arrayt::{AsSlice, NewArray},
        kemt::{KemT, ToEncapsKeyT},
        sigt::{SigT, ToVerifyingKeyT}
    }
};

use crate::{
    archive::NONCE_NULL,
    config::Config,
    errors::{Error, Result},
    utils::{
        read_buf_var,
        gen_uuidv4_from_hash
    },
    MAX_STRING_LENGTH,
    PRIVATE_EXTENSION,
    PUBLIC_EXTENSION,
    VERSION_FORMAT
};

pub(crate) const MAGIC_PUBLIC:  &[u8; 10] = b"FaSEAL/pub";
const MAGIC_PRIVATE: &[u8; 10] = b"FaSEAL/prv";
pub(crate) const VERSION_KEY: &[u8; 4] = VERSION_FORMAT;
const SALT_LENGTH: usize = 16;
pub(crate) const DEFAULT_MIN_PASSWORD_LENGTH: usize = 12;

pub struct IdentityPub<KEM: KemT, SIG: SigT> {
    uuid: String,
    name: String,
    contact: String,
    comment: String,
    verifying_key: SIG::VerifyingKey,
    encaps_key: KEM::EncapsKey,
    signature: SIG::Signature,
}

pub struct IdentityPrv<KEM: KemT, SIG: SigT> {
    name: String,
    contact: String,
    comment: String,
    signing_key: SIG::SigningKey,
    decaps_key: KEM::DecapsKey,
    public: IdentityPub<KEM, SIG>,
    params: Argon2Params
}

impl<KEM: KemT, SIG: SigT> PartialEq for IdentityPub<KEM, SIG> {
    fn eq(&self, other: &Self) -> bool {
        self.uuid.eq(&other.uuid)
        && self.name.eq(&other.name)
        && self.contact.eq(&other.contact)
        && self.comment.eq(&other.comment)
        && self.verifying_key.eq(&other.verifying_key)
        && self.encaps_key.eq(&other.encaps_key)
        && self.signature.eq(&other.signature)
    }
}

impl<KEM: KemT, SIG: SigT> Eq for IdentityPub<KEM, SIG> {}

impl<KEM: KemT, SIG: SigT> IdentityPub<KEM, SIG> {
    fn create(
        name: &str,
        contact: &str,
        comment: &str,
        signing_key: &SIG::SigningKey,
        verifying_key: &SIG::VerifyingKey,
        encaps_key: &KEM::EncapsKey,
    ) -> Self {
        // hash all data that must be signed
        let mut signer = Sha3_512::init();
        signer.update(MAGIC_PUBLIC);
        signer.update(VERSION_KEY);
        signer.update(&(name.len() as u64).to_le_bytes());
        signer.update(name.as_bytes());
        signer.update(&(contact.len() as u64).to_le_bytes());
        signer.update(contact.as_bytes());
        signer.update(&(comment.len() as u64).to_le_bytes());
        signer.update(comment.as_bytes());
        signer.update(verifying_key.as_slice());
        signer.update(encaps_key.as_slice());
        let msg = signer.finalize();

        Self {
            uuid: gen_uuidv4_from_hash(&msg),
            name: name.to_string(),
            contact: contact.to_string(),
            comment: comment.to_string(),
            verifying_key: verifying_key.clone(),
            encaps_key: encaps_key.clone(),
            signature: SIG::sign(signing_key, &msg)
        }
    }

    fn new(
        name: &str,
        contact: &str,
        comment: &str,
        verifying_key: &SIG::VerifyingKey,
        encaps_key: &KEM::EncapsKey,
        signature: &SIG::Signature
    ) -> Result<Self> {
        // hash all data that must be signed
        let mut verifier = Sha3_512::init();
        verifier.update(MAGIC_PUBLIC);
        verifier.update(VERSION_KEY);
        verifier.update(&(name.len() as u64).to_le_bytes());
        verifier.update(name.as_bytes());
        verifier.update(&(contact.len() as u64).to_le_bytes());
        verifier.update(contact.as_bytes());
        verifier.update(&(comment.len() as u64).to_le_bytes());
        verifier.update(comment.as_bytes());
        verifier.update(verifying_key.as_slice());
        verifier.update(encaps_key.as_slice());
        let msg = verifier.finalize();

        match SIG::verify(verifying_key, &msg, signature) {
            Ok(()) => Ok(
                Self {
                    uuid: gen_uuidv4_from_hash(&msg),
                    name: name.to_string(),
                    contact: contact.to_string(),
                    comment: comment.to_string(),
                    verifying_key: verifying_key.clone(),
                    encaps_key: encaps_key.clone(),
                    signature: signature.clone()
                }
            ),
            Err(err) => Err(Error::Signature(err))
        }
    }

    pub  fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn contact(&self) -> &str {
        &self.contact
    }

    pub fn comment(&self) -> &str {
        &self.comment
    }

    pub fn encaps_key(&self) -> &KEM::EncapsKey {
        &self.encaps_key
    }

    pub fn verifying_key(&self) -> &SIG::VerifyingKey {
        &self.verifying_key
    }

    pub(crate) fn dump(&self) -> Result<Vec<u8>> {
        let mut buf = BufWriter::new(Vec::<u8>::new());
        buf.write_all(&(self.name.len() as u64).to_le_bytes())?;
        buf.write_all(self.name.as_bytes())?;
        buf.write_all(&(self.contact.len() as u64).to_le_bytes())?;
        buf.write_all(self.contact.as_bytes())?;
        buf.write_all(&(self.comment.len() as u64).to_le_bytes())?;
        buf.write_all(self.comment.as_bytes())?;
        buf.write_all(self.verifying_key.as_slice())?;
        buf.write_all(self.encaps_key.as_slice())?;
        buf.write_all(self.signature.as_slice())?;
        buf.into_inner().map_err(|e| e.into_error().into())
    }

    // Load from a reader (file or slice)
    // `verifier` has already consumed `MAGIC_PUBLIC` and `VERSION_KEY`
    fn load_from_reader<R: Read>(
        reader: &mut BufReader<R>,
        verifier: &mut Sha3_512,
    ) -> Result<Self> {
        let mut buf_len = [0u8; 8];
        // --- data ---
        // name
        let buf = read_buf_var(reader, &mut buf_len, MAX_STRING_LENGTH)?;
        let name = String::from_utf8(buf)?;
        verifier.update(&buf_len);
        verifier.update(name.as_bytes());

        // contact
        let buf = read_buf_var(reader, &mut buf_len, MAX_STRING_LENGTH)?;
        let contact = String::from_utf8(buf)?;
        verifier.update(&buf_len);
        verifier.update(contact.as_bytes());

        // comment
        let buf = read_buf_var(reader, &mut buf_len, MAX_STRING_LENGTH)?;
        let comment = String::from_utf8(buf)?;
        verifier.update(&buf_len);
        verifier.update(comment.as_bytes());

        // verifying key
        let mut verifying_key = SIG::VerifyingKey::new();
        reader.read_exact(verifying_key.as_mut_slice())?;
        verifier.update(verifying_key.as_slice());

        // encaps key
        let mut encaps_key = KEM::EncapsKey::new();
        reader.read_exact(encaps_key.as_mut_slice())?;
        verifier.update(encaps_key.as_slice());

        // --- signature ---
        let mut signature = SIG::Signature::new();
        reader.read_exact(signature.as_mut_slice())?;
        let msg = verifier.finalize();
        SIG::verify(&verifying_key, &msg, &signature)?;

        // extra bytes
        if reader.read(&mut [0u8])? > 0 {
            return Err(Error::PublicIdCorrupted);
        }

        Ok(Self {
            uuid: gen_uuidv4_from_hash(&msg),
            name,
            contact,
            comment,
            encaps_key,
            verifying_key,
            signature
        })
    }

    pub(crate) fn load_from_dump(dump: &[u8]) -> Result<Self> {
        let mut reader = BufReader::new(dump);
        let mut verifier = Sha3_512::init();
        verifier.update(MAGIC_PUBLIC);
        verifier.update(VERSION_KEY);
        Self::load_from_reader(&mut reader, &mut verifier)
    }

    pub fn load_from_file(fname: &Path) -> Result<Self> {
        let mut reader = BufReader::new(File::open(fname)?);
        let mut verifier = Sha3_512::init();

        // --- header ---
        // magic
        let mut magic = [0u8; MAGIC_PUBLIC.len()];
        reader.read_exact(&mut magic)?;
        if !magic.eq(MAGIC_PUBLIC) {
            return Err(Error::NotPublicId);
        }
        verifier.update(MAGIC_PUBLIC);

        // version
        let mut version = [0u8; VERSION_KEY.len()];
        reader.read_exact(&mut version)?;
        if !version.eq(VERSION_KEY) {
            return Err(Error::PublicIdUnsupportedVersion);
        }
        verifier.update(&version);

        // --- everything else ---
        Self::load_from_reader(&mut reader, &mut verifier)
    }
}

impl<KEM: KemT, SIG: SigT> IdentityPrv<KEM, SIG> {
    pub(crate) fn create(
        name: &str,
        contact: &str,
        comment: &str,
        params: Argon2Params
    ) -> Result<Self> {
        let (signing_key, verifying_key) = SIG::keygen();
        let (encaps_key, decaps_key) = KEM::keygen();
        let public = IdentityPub::create(
            name,
            contact,
            comment,
            &signing_key,
            &verifying_key,
            &encaps_key
        );
        Ok(
            Self {
                name: name.to_string(),
                contact: contact.to_string(),
                comment: comment.to_string(),
                signing_key,
                decaps_key,
                public,
                params
            }
        )
    }

    pub fn load_from_file(password: &SecretString, fname: &Path) -> Result<Self> {
        let mut file = BufReader::new(File::open(fname)?);
        let mut header_buf = BufWriter::new(Vec::<u8>::new());

        // --- header ---
        // magic
        let mut magic = [0u8; MAGIC_PRIVATE.len()];
        file.read_exact(&mut magic)?;
        if !magic.eq(MAGIC_PRIVATE) {
            return Err(Error::NotPrivateId);
        }
        header_buf.write_all(&magic)?;

        // version
        let mut version = [0u8; VERSION_KEY.len()];
        file.read_exact(&mut version)?;
        if !version.eq(VERSION_KEY) {
            return Err(Error::PrivateIdUnsupportedVersion);
        }
        header_buf.write_all(&version)?;
        
        // Argon2 parameters
        let mut buf = [0u8; 12];
        file.read_exact(&mut buf)?;
        let cost_m = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let cost_p = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        let cost_t = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
        header_buf.write_all(&buf)?;

        // salt
        let mut salt = vec![0u8; SALT_LENGTH];
        file.read_exact(&mut salt)?;
        header_buf.write_all(&salt)?;

        // add header for signature verification
        let header_buf = header_buf.into_inner().map_err(|e| e.into_error())?;
        let mut verifier = Sha3_512::init();
        verifier.update(&header_buf);

        // -- encrypted part ---
        let mut buf_len = [0u8; 8];
        let mut encrypted_buf = read_buf_var(
            &mut file,
            &mut buf_len,
            3 * MAX_STRING_LENGTH
                + KEM::ENCAPSKEY_LEN
                + SIG::VERIFYINGKEY_LEN
                + SIG::SIGNATURE_LEN
        )?;
        let mut tag = [0u8; TAG_LENGTH];
        file.read_exact(&mut tag)?;

        // add encrypted part for signature verification
        verifier.update(&buf_len);
        verifier.update(&encrypted_buf);
        verifier.update(&tag);

        // --- signature ---
        let mut signature = SIG::Signature::new();
        file.read_exact(signature.as_mut_slice())?;
        
        // verify that no extra bytes are appended to the file
        if file.read(&mut [0u8])? > 0 {
            return Err(Error::PrivateIdCorrupted);
        }

        // --- decryption ---
        let mut key = ZeroizeArray::<KEY_LENGTH>::new();
        let params = Argon2Params::new(cost_m, cost_p, cost_t);
        Argon2::hash_into(password, &salt, &[], MAGIC_PRIVATE, &params, key.as_mut())?;

        ChaCha20Poly1305::new(key.as_ref(), NONCE_NULL)
            .decrypt_in_place(&header_buf, &mut encrypted_buf, &tag)?;

        // --- parse decrypted buffer ---
        let mut reader = BufReader::new(encrypted_buf.as_slice());
        
        // name
        let buf = read_buf_var(&mut reader, &mut buf_len, MAX_STRING_LENGTH)?;
        let name = String::from_utf8(buf)?;

        // contact
        let buf = read_buf_var(&mut reader, &mut buf_len, MAX_STRING_LENGTH)?;
        let contact = String::from_utf8(buf)?;

        // comment
        let buf = read_buf_var(&mut reader, &mut buf_len, MAX_STRING_LENGTH)?;
        let comment = String::from_utf8(buf)?;

        // signing key
        let mut signing_key = SIG::SigningKey::new();
        reader.read_exact(signing_key.as_mut_slice())?;
        let verifying_key = signing_key.to_verifying_key();

        // decaps key
        let mut decaps_key = KEM::DecapsKey::new();
        reader.read_exact(decaps_key.as_mut_slice())?;
        let encaps_key = decaps_key.to_encaps_key();

        // public key signature
        let mut public_signature = SIG::Signature::new();
        reader.read_exact(public_signature.as_mut_slice())?;

        // destroy content of encrypted_buf
        encrypted_buf.zeroize();

        // verify signature
        let msg = verifier.finalize();
        SIG::verify(&verifying_key, &msg, &signature)?;

        // public identity
        let public = IdentityPub::new(
            &name,
            &contact,
            &comment,
            &verifying_key,
            &encaps_key,
            &public_signature
        )?;
        
        Ok(Self {
            name,
            contact,
            comment,
            decaps_key,
            signing_key,
            public,
            params
        })
    }

    fn save_private_to_file(
        &self,
        password: &SecretString,
        fname: &Path,
        config: &Config
    ) -> Result<()> {
        if password.expose_secret().chars().count() < config.min_password_length() {
            return Err(Error::PasswordTooShort(config.min_password_length()))
        }
        
        let mut file = BufWriter::new(File::create(fname)?);
        let mut header_buf = BufWriter::new(Vec::<u8>::new());
        
        // --- header ---
        // magic and version
        header_buf.write_all(MAGIC_PRIVATE)?;
        header_buf.write_all(VERSION_KEY)?;

        // Argon2 parameters and salt for password hashing
        header_buf.write_all(&self.params.cost_m().to_le_bytes())?;
        header_buf.write_all(&self.params.cost_p().to_le_bytes())?;
        header_buf.write_all(&self.params.cost_t().to_le_bytes())?;
        let mut salt = [0u8; SALT_LENGTH];
        rand::rng().fill_bytes(&mut salt);
        header_buf.write_all(&salt)?;

        let header_buf = header_buf.into_inner().map_err(|e| e.into_error())?;

        // --- encryped part ---
        let mut encrypted_buf = BufWriter::new(Vec::<u8>::new());

        // name
        encrypted_buf.write_all(&(self.name.len() as u64).to_le_bytes())?;
        encrypted_buf.write_all(self.name.as_bytes())?;

        // contact
        encrypted_buf.write_all(&(self.contact.len() as u64).to_le_bytes())?;
        encrypted_buf.write_all(self.contact.as_bytes())?;
        
        // comment
        encrypted_buf.write_all(&(self.comment.len() as u64).to_le_bytes())?;
        encrypted_buf.write_all(self.comment.as_bytes())?;

        // signing and decaps keys
        encrypted_buf.write_all(self.signing_key.as_slice())?;
        encrypted_buf.write_all(self.decaps_key.as_slice())?;

        // signature of public key
        encrypted_buf.write_all(self.public.signature.as_slice())?;

        let mut encrypted_buf = encrypted_buf.into_inner().map_err(|e| e.into_error())?;

        // derive key for AEAD encryption
        let mut key = ZeroizeArray::<KEY_LENGTH>::new();
        Argon2::hash_into(password, &salt, &[], MAGIC_PRIVATE, &self.params, key.as_mut())?;

        // encrypt with header as AAD (nonce is null since a salt is already used
        // to derive the key from passwprd)
        let tag = ChaCha20Poly1305::new(key.as_ref(), NONCE_NULL)
            .encrypt_in_place(&header_buf, &mut encrypted_buf);

        // sign everything
        let mut signer = Sha3_512::init();
        signer.update(&header_buf);
        signer.update(&(encrypted_buf.len() as u64).to_le_bytes());
        signer.update(&encrypted_buf);
        signer.update(&tag);
        let msg = signer.finalize();
        let signature = SIG::sign(&self.signing_key, &msg);

        // write everything to file
        file.write_all(&header_buf)?;
        file.write_all(&(encrypted_buf.len() as u64).to_le_bytes())?;
        file.write_all(&encrypted_buf)?;
        file.write_all(&tag)?;
        file.write_all(signature.as_slice())?;
        file.flush()?;
        Ok(())
    }

    fn save_private_to_config_path(
        &self,
        password: &SecretString,
        config: &mut Config,
        make_default: bool
    ) -> Result<()> {
        let path = config.private_dir_path()
            .join(format!("{}_{}", self.name, self.public.uuid))
            .with_extension(PRIVATE_EXTENSION);
        self.save_private_to_file(password, &path, config)?;
        if make_default {
            config.set_main_private_id_path(path);
            config.write_config_file()?;
        }
        Ok(())
    }

    fn set_params(&mut self, params: Argon2Params) {
        self.params = params;
    }

    pub fn params(&self) -> &Argon2Params {
        &self.params
    }

    pub fn public_ref(&self) -> &IdentityPub<KEM, SIG> {
        &self.public
    }

    #[cfg(test)]
    pub(crate) fn public(&self) -> IdentityPub<KEM, SIG> {
        IdentityPub {
            uuid: self.public.uuid.to_string(),
            name: self.public.name.clone(),
            contact: self.public.contact.clone(),
            comment: self.public.comment.clone(),
            verifying_key: self.public.verifying_key.clone(),
            encaps_key: self.public.encaps_key.clone(),
            signature: self.public.signature.clone()
        }
    }

    pub(crate) fn decaps_key(&self) -> &KEM::DecapsKey {
        &self.decaps_key
    }

    pub(crate) fn signing_key(&self) -> &SIG::SigningKey {
        &self.signing_key
    }

    fn save_public_to_file(&self, fname: &Path) -> Result<()> {
        let mut file = BufWriter::new(File::create(fname)?);
        
        // magic and version
        file.write_all(MAGIC_PUBLIC)?;
        file.write_all(VERSION_KEY)?;
        
        // name
        file.write_all(&(self.name.len() as u64).to_le_bytes())?;
        file.write_all(self.name.as_bytes())?;

        // contact
        file.write_all(&(self.contact.len() as u64).to_le_bytes())?;
        file.write_all(self.contact.as_bytes())?;

        // commennt
        file.write_all(&(self.comment.len() as u64).to_le_bytes())?;
        file.write_all(self.comment.as_bytes())?;

        // verifying and encaps keys
        file.write_all(self.public.verifying_key.as_slice())?;
        file.write_all(self.public.encaps_key.as_slice())?;

        // signature
        file.write_all(self.public.signature.as_slice())?;
        file.flush()?;

        Ok(())
    }

    fn save_public_to_config_path(&self, config: &Config) -> Result<()> {
        let path = config.public_dir_path()
            .join(format!("{}_{}", self.name, self.public.uuid))
            .with_extension(PUBLIC_EXTENSION);
        self.save_public_to_file(&path)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn keygen<KEM: KemT, SIG: SigT>(
    name: &str,
    contact: &str,
    comment: &str,
    password: &SecretString,
    confirm_password: &SecretString,
    params: Argon2Params,
    config: &mut Config,
    make_default: bool
) -> Result<()> {
    if password
        .expose_secret()
        .as_bytes()
        .ct_ne(confirm_password.expose_secret().as_bytes())
        .into()
    {
        return Err(Error::ConfirmationPasswordDoesNotMatch);
    }
    // create the private identity and save into files
    let private_id = IdentityPrv::<KEM, SIG>::create(name, contact, comment, params)?;
    private_id.save_private_to_config_path(password, config, make_default)?;
    private_id.save_public_to_config_path(config)
}

pub fn change_password<KEM: KemT, SIG: SigT>(
    private_id: &mut IdentityPrv<KEM, SIG>,
    private_path: &Path,
    new_password: &SecretString,
    new_password_confirm: &SecretString,
    params: Argon2Params,
    config: &Config
) -> Result<()> {
    if new_password
        .expose_secret()
        .as_bytes()
        .ct_ne(new_password_confirm.expose_secret().as_bytes())
        .into()
    {
        return Err(Error::ConfirmationPasswordDoesNotMatch);
    }

    private_id.set_params(params);
    private_id.save_private_to_file(new_password, private_path, config)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use faseal_crypto::kem::MlKem768X25519;
    use faseal_crypto::sig::MlDsa65Ed25519;
    use faseal_crypto::argon2::Argon2Params;
    use tempfile::TempDir;

    type IdentityPrv = crate::IdentityPrv<MlKem768X25519, MlDsa65Ed25519>;
    type IdentityPub = crate::IdentityPub<MlKem768X25519, MlDsa65Ed25519>;

    #[test]
    fn test_identity_private() {
        let tmp_dir = TempDir::new().unwrap();
        let private_id = IdentityPrv::create(
            "Alice TEST",
            "alice@wonderland.org",
            "no comment",
            Argon2Params::default()
        ).unwrap();
        // let params = Argon2Params::default();
        let password = SecretString::from("passwordpass");
        let badpassword = SecretString::from("badpasswordpass");
        let private_path = tmp_dir.path().join("alice_test.fprv");
        let mut config = Config::new();
        config.set_private_dir_path(tmp_dir.path().to_path_buf());
        config.set_public_dir_path(tmp_dir.path().to_path_buf());

        private_id.save_private_to_file(
            &password,
            &private_path,
            &config
        ).unwrap();

        let other_private_id = IdentityPrv::load_from_file(&password, &private_path).unwrap();
        
        assert!(IdentityPrv::load_from_file(&badpassword, &private_path).is_err());
        assert_eq!(other_private_id.name, private_id.name);
        assert_eq!(other_private_id.contact, other_private_id.contact);
        assert_eq!(other_private_id.comment, other_private_id.comment);
        assert_eq!(
            other_private_id.decaps_key.as_ref(),
            private_id.decaps_key.as_ref()
        );
        assert_eq!(
            other_private_id.public.encaps_key.as_ref(),
            private_id.public.encaps_key.as_ref()
        );
        assert_eq!(
            other_private_id.signing_key.as_ref(),
            private_id.signing_key.as_ref()
        );
        assert_eq!(
            other_private_id.public.verifying_key.as_ref(),
            private_id.public.verifying_key.as_ref()
        );
        assert!(other_private_id.public.eq(&private_id.public));
        assert_eq!(other_private_id.params.cost_m(), private_id.params.cost_m());
        assert_eq!(other_private_id.params.cost_p(), private_id.params.cost_p());
        assert_eq!(other_private_id.params.cost_t(), private_id.params.cost_t());
        assert_eq!(other_private_id.params.tag_length(), private_id.params.tag_length());
        assert_eq!(other_private_id.params.r#type(), private_id.params.r#type());
    }

    #[test]
    fn test_identity_public() {
        let tmp_dir = TempDir::new().unwrap();
        let private_id = IdentityPrv::create(
            "Alice TEST",
            "alice@wonderland.org",
            "no comment",
            Argon2Params::default()
        ).unwrap();
        let public_path = tmp_dir.path().join("alice_test.fpub");
        private_id.save_public_to_file(&public_path).unwrap();

        let public_id_1 = private_id.public;
        let public_id_2 = IdentityPub::load_from_file(&public_path).unwrap();
        
        assert_eq!(public_id_1.name, public_id_2.name);
        assert_eq!(public_id_1.encaps_key.as_ref(), public_id_2.encaps_key.as_ref());
        assert_eq!(public_id_1.verifying_key.as_ref(), public_id_2.verifying_key.as_ref());
        assert_eq!(public_id_1.signature.as_ref(), public_id_2.signature.as_ref());

        let mut buf = Vec::<u8>::new();
        buf.extend_from_slice(MAGIC_PUBLIC);
        buf.extend_from_slice(VERSION_KEY);
        buf.extend(public_id_1.dump().unwrap());
        let public_file = std::fs::read(public_path).unwrap();
        
        assert_eq!(buf, public_file);
    }
}
