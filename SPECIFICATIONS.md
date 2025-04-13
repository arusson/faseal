# FaSEAL - Specifications

This document is a draft for specifications of FaSEAL version 0.1.0.

## Cryptographic mechanisms

All cryptographic mechanisms used are listed below:
- Hashes:
  * **Blake2b**: used internally in Argon2id ([RFC-7693](https://datatracker.ietf.org/doc/html/rfc7693.html));
  * **SHA3-256**, **SHA3-512**, **SHAKE128** and **SHAKE256**: used for ML-KEM and ML-DSA, with SHA3-512 as main hash function in core application ([FIPS 202](https://csrc.nist.gov/pubs/fips/202/final));
  * **SHA-512**: used internally in Ed25519 ([FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)).
- Password-based key derivation:
  * **Argon2id**: for private key protection ([RFC-9106](https://datatracker.ietf.org/doc/html/rfc9106)).
- AEAD (authenticated encryption with associated data):
  * **ChaCha20Poly305**: encryption of archives and private keys ([RFC 7539](https://datatracker.ietf.org/doc/html/rfc7539)).
- KEM:
  * Hybridization: **X-Wing** ([RFC draft](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/));
  * **ML-KEM-768** ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final));
  * **X25519** ([RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748)).
- Signature:
  * Hybridization: **strong-nesting**;
  * **ML-DSA-65** ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final));
  * **Ed25519** ([RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)).

## Lengths of asymmetric mechanisms

The following variables are used for the lengths of asymmetric mechanisms:
- KEM:
  * `DK_LEN`: length of decapsulation key;
  * `EK_LEN`: length of encapsulation key;
  * `CT_LEN`: length of ciphertext.
- Signature:
  * `SK_LEN`: length of signing key;
  * `VK_LEN`: length of verifying key;
  * `SIG_LEN`: length of signature.

The individual algorithm key lengths in bytes are:
- ML-KEM-768:
  * Decapsulation key: 2400;
  * Encapsulation key: 1184;
  * Ciphertext: 1088.
- ML-DSA-65:
  * Signing key: 4032;
  * Verifying key: 1952;
  * Signature: 3309.
- X25519:
  * Secret key: 32;
  * Public key: 32;
  * Shared secret: 32.
- Ed25519:
  * Signing key: 32;
  * Verifying key: 32;
  * Signature: 64.

For hybridization, keys, signatures, and ciphertexts are stored concatenated.

For ML-KEM-768-X25519, the X25519 public key is added to the decapsulation key to avoid recalculation for its use in the X-Wing combiner (ML-KEM has natively a copy of the encapsulation key inside the decapsulation key).

| `DK_LEN`                   | `EK_LEN`              | `CT_LEN` |
| -------------------------- | --------------------- | -------- |
| 2464 <br> (2400 + 32 + 32) | 1216 <br> (1184 + 32) | 1120 <br> (1088 + 32) |

For ML-DSA-65-Ed25519, the verifying keys of both signature mechanisms are included in the signing keys to make it easier to extract them (the verifying key for Ed25519 is needed for signature generation).

| `SK_LEN`                          | `VK_LEN`              | `SIG_LEN` |
| --------------------------------- | --------------------- | --------- |
| 6048 <br> (4032 + 1952 + 32 + 32) | 1984 <br> (1952 + 32) | 3373 <br> (3309 + 64)


## Signature generation

A signature in FaSEAL uses a strong-nested hybridization.
It is generated as follows:
1. Hash the content *buffer* with SHA3-512 and get the output *h*;
2. Consider *h* as the message to sign:
   + Use the signing key to sign the buffer with ML-DSA-65;
   + Use the signing key to sign the buffer concatenated with the previous signature with Ed25519;
   + Concatenate the signatures.
  
> [!NOTE]
> The signature protocol described above can be interpreted as a pre-hash signature.
> However, it does not use the pre-hash variant of the algorithms.
> This choice is deliberate: FaSEAL considers that the message to sign is a hash.
> Furthermore, signing keys are supposed to be used only in the application (to sign archives and keys).

The content to hash in each case is described below.

## Private key format

A private key is stored in raw format.
Its file extension is `.fprv`.

Each buffer that represents a length is in little-endian order.

| Element           | Length (bytes) | Description                                                                               |
| ----------------- | -------------- | ----------------------------------------------------------------------------------------- |
| Magic             | 10             | string "FaSEAL/prv"                                                                       |
| Version           | 4              | key version (used for compatibility <br> in case of breaking changes in a future version) |
| Argon2 parameters | 12             | memory cost (4 bytes) <br> parallel cost (4 bytes)<br> iteration cost (4 bytes)           |
| Salt              | 16             | salt for key derivation in Argon2id                                                       |
| Encrypted length  | 8              | length of the encrypted buffer that follows                                               |
| Encrypted buffer  | var            | contains user information and secret keys                                                 |
| Tag               | 16             | authentication tag for the encrypted buffer                                               |
| Signature         | `SIG_LEN`      | signature for the whole content of the private key file                                   |

The encrypted buffer content in plaintext is given in the following table.

| Element              | Length (bytes) | Description                                   |
| -------------------- | -------------- | ----------------------------------------------|
| Name length          | 8              | length of the key owner's name                |
| Name                 | var            | the key owner's name (UTF-8 encoding)         |
| Contact length       | 8              | length of the key owner's contact information |
| Contact              | var            | the key owner's contact information           |
| Comment length       | 8              | length of the key owner's comment information |
| Comment              | var            | the key owner's contact information           |
| Signing key          | `SK_LEN`       | buffer containing the signing key             |
| Decapsulation key    | `DK_LEN`       | buffer containing the decapsulation key       |
| Public key signature | `SIG_LEN`      | signature of the public key                   |

The encryption is done as follows:
1. Let `buffer` be the whole content described in the previous table;
2. Derive a symmetric key $k_{\rm prv}$ with Argon2id and these parameters:
   - Password: the user password as UTF-8 encoded bytes;
   - Salt: a fresh salt of 16 bytes randomly generated (stored in the header);
   - Secret value: not used (optional in the specification of Argon2);
   - Associated data: magic private "FaSEAL/prv";
   - Cost parameters (same default values as libsodium):
     + Memory cost (default is 16 MiB);
     + Parallel cost (default is 1);
     + Iteration cost (default is 3).
   - Tag length: 32 bytes.
3. Encrypt `buffer` with the AEAD algorithm:
   - Key: the symmetric key $k_{\rm prv}$;
   - Nonce: null bytes (the key has a unique usage);
   - Associated data: header of the private key file (magic to salt).

The signature is generated with:
- the signing key that is encrypted inside the file;
- the content from magic to the authentication tag.

## Public key format
 
The format is almost the same, but nothing is encrypted.
Its file extension is `.fpub`.

| Element             | Length (bytes) | Description                                                                                      |
|---------------------|----------------| ------------------------------------------------------------------------------------------------ |
| Magic               | 10             | string "FaSEAL/pub"                                                                              |
| Version             | 4              | key format version (used for compatibility <br> in case of breaking changes in a future version) |
| Name length         | 8              | length of the key owner's name                                                                   |
| Name                | var            | the key owner's name (UTF-8 encoding)                                                            |
| Contact length      | 8              | length of the key owner's contact information                                                    |
| Contact             | var            | the key owner's contact information                                                              |
| Comment length      | 8              | length of the key owner's comment information                                                    |
| Comment             | var            | the key owner's comment information                                                              |
| Verifying key       | `VK_LEN`       | buffer containing the verifying key                                                              |
| Encapsulation key   | `EK_LEN`       | buffer containing the encapsulation key                                                          |
| Signature           | `SIG_LEN`      | signature for the whole content of the public key                                                |

The signature is generated with:
- the signing key that corresponds to the verifying key;
- the content from magic to the encapsulation key.

## Archive format

The archive format is as follows.

| Element                     | Length (bytes) | Description                                                                                          |
| ------------------------    |----------------|----------------------------------------------------------------------------------------------------- |
| Magic                       | 10             | string "FaSEAL/arc"                                                                                  |
| Version                     | 4              | archive format version (used for compatibility <br> in case of breaking changes in a future version) |
| Encapsulation zone length   | 8              | length of the encapsulation zone                                                                     |
| Encapsulation zone          | var            | archive master key encrypted for each recipient <br> using their encapsulating keys                  |
| Length zone (encrypted)     | 56             | lengths of public key zone, file name zone, file zone <br> and a secret random value                       |
| Length zone tag             | 16             | authentication tag for the length zone                                                               |
| Public key zone (encrypted) | var            | public keys of recipients                                                                            |
| Public key zone tag         | 16             | authentication tag for the public key zone                                                           |
| File name zone (encrypted)  | var            | files metadata (name, length, list of compressed chunk sizes)                                        |
| File name zone tag          | 16             | authentication tag for file name zone                                                                 |
| File zone (encrypted)       | var            | compressed chunks of files                                                                           |
| File zone tag               | 16             | authentication tag for file zone                                                                     |
| Signature                   | `SIG_LEN`      | signature of the whole archive                                                                       |

The construction of each zone is explained below.

### Encapsulation zone

The encapsulation zone format is as follows:

| Element                | Length (bytes) | Description                                                       |
| ---------------------- | -------------- | ----------------------------------------------------------------- |
| Number of recipients   | 8              | number of recipients of the archive (creator included)            |
| Ciphertext             | `CT_LEN`       | ciphertext obtained with the creator's encapsulation key          |
| Master key (encrypted) | 32             | archive master key, encrypted with shared secret for the creator  |
| Master key tag         | 16             | authentication tag for the encrypted master key                   |
| ...                    | ...            | the three previous fields are repeated for each recipient         |

For each recipient (including the creator):
- a ciphertext $c$ and a shared secret $k$ are obtained using the recipient KEM encapsulating key;
- the master key of the archive is encrypted using $k$:
  * Key: the shared secret $k$;
  * Nonce: null (the key has a unique usage);
  * Associated data: "encaps".

### Length zone

The length zone format is as follows:

| Element                 | Length (bytes) | Description                               |
| ----------------------- | -------------- | ----------------------------------------- |
| Public key zone length  | 8              | length of the public key zone             |
| File name zone length   | 8              | length of the file name zone              |
| File zone length        | 8              | length of the file zone                   |
| Secret random           | 32             | a secret value for signature verification |

This zone must be constructed after all lengths are known.
It is encrypted with the AEAD algorithm:
  - Key: the archive master key $K$;
  - Nonce: null bytes (only used for this zone);
  - Associated data: hash of the encapsulated zone with SHA3-512.

### Public key zone

| Element                | Length (bytes) | Description                                             |
| ---------------------- | -------------- | ------------------------------------------------------- |
| Public key dump length | 8              | length of creator's public key dump                     |
| Public key dump        | var            | public key of the creator without magic and version     |
| ...                    | ...            | the two previous fields are repeated for each recipient |

The magic and version fields of a public key are not included since they are supposed to be the same for all.
When the archive is opened, those two elements are taken into account for the signature verification.

This zone is encrypted with the AEAD algorithm:
  - Key: the archive master key $K$;
  - Nonce: 1 (only used for this zone);
  - Associated data: hash of the encapsulated zone with SHA3-512.

### File name zone

For one file, the format is as follows:

| Element            | Length (bytes) | Description                                       |
| ------------------ | -------------- | ------------------------------------------------- |
| Flag               | 1              | value that indicates a file (0)                   |
| File name length   | 8              | length of the file name (as UTF-8 encoded bytes)  |
| File name          | var            | file name (UTF-8 encoding)                        |
| Position           | 8              | position of the file in the file zone             |
| Compressed length  | 8              | length of the compressed file                     |
| Length             | 8              | length of the file                                |
| Chunk size length  | 8              | number of compressed chunks that compose the file |
| Chunk size         | 4              | length of first compressed chunk                  |
| ...                | ...            | the previous field is repeated for each chunk     |

For one folder, the format is as follows:

| Element            | Length (bytes) | Description                                                      |
| ------------------ | -------------- | ---------------------------------------------------------------- |
| Flag               | 1              | value that indicates a folder (1)                                |
| Folder name length | 8              | length of the folder name (as UTF-8 encoded bytes)               |
| Folder name        | var            | folder name (UTF-8 encoding)                                     |
| ...                | ...            | files or folders with this format <br> (included in this folder) |
| Flag               | 1              | value that indicates the end of the folder (253)                 |

Finally, the file name zone format is as follows:

| Element           | Length (bytes) | Description                                           |
|-------------------|----------------|-------------------------------------------------------|
| Files and folders | ...            | files or folders according the format specified above |
| Flag              | 1              | value that indicates the end of the zone (254)        |

This zone is encrypted with the AEAD algorithm:
  - Key: the archive master key $K$;
  - Nonce: 2 (only used for this zone);
  - Associated data: hash of the encapsulated zone with SHA3-512.

### File zone

This zone is the simplest of all:
- each file is separated in chunks of 1 MB;
- each chunk is compressed using the Brotli compression algorithm;
- compressed chunks are concatenated to each other;
- the length of each compressed chunks is saved in the file name zone.

It is encrypted with the AEAD algorithm:
  - Key: the archive master key $K$;
  - Nonce: 3 (only used for this zone);
  - Associated data: hash of the encapsulated zone with SHA3-512.

### Archive construction

An archive is constructed from the following inputs:
- A private identity: the archive creator;
- Public identities: 0 or more recipients;
- Input paths: a list of paths of files and/or folders to add in the archive;
- Output path: the path for the output of the archive;
- Compression level: an integer for the Brotli compression level (default: 9).

The steps of the construction are as follows:
1. Verification if the files/folders added to the root of the archive have different names (*);
2. Generate a fresh **symmetric master key** $K$ (32 bytes), and a secret random value $m$ (32 bytes);
3. Creation of the **encapsulation zone** according to its format;
4. Generate *AD* as the hash of the **encapsulation zone** with SHA3-512;
5. Creation of the **public key zone** according to its format;
6. Creation of the **file name zone** according to its format;
7. Creation of the **file zone** according to its format;
8. Creation of the **length zone** according to its format;
9. Generate the archive **signature** with:
   - The signing key of the creator;
   - The content is:
     * magic to file zone;
     * The secret random $m$.
10. Create the archive file according to its format.

> (*) For example, while `folder1/file1.txt` and `folder2/file1.txt` refer to different files in the system, if those files are added at the root of the archives, then only `file1.txt` would be kept as path in the archive for both files, which would result in a conflict during extraction.

### Archive opening

The following steps have to be performed:
1. Read and verification of the magic value and version;
2. Read the **encapsulation zone** and compute its hash as *AD*;
3. Retrieve the archive **master key**:
   - Read the number of recipients and verify that the **encapsulation zone** length is consistent with the number of public identities (no extra bytes allowed);
   - Read a ciphertext and decapsulate using the private key;
   - Read 32 bytes encrypted master key and its 16 bytes tag;
   - Decrypt the archive master key with the shared secret obtained from decapsulation;
   - In case of decryption failure, continue with next ciphertext;
   - If all decryptions failed, STOP the process: the private key owner is not a recipient.
4. Read the **length zone**:
   - Decrypt it using the master key;
   - Verify that the lengths are consistent with the file length.
5. Read the **public key zone**:
   - Use the length to retrieve the encrypted public key zone and its authentication tag;
   - Decrypt it using the master key;
   - Take first public key and consider it as the archive creator's public key;
   - Load all other public keys of the recipients;
   - Verify that the position of the opener public key is at the same as the ciphertext in the encapsulation zone;
   - Verify that no extra bytes are present in the public key zone.
6. Read the **file name zone**:
   - Use the length to retrieve the encrypted file name zone and its authentication tag;
   - Decrypt it using the master key;
   - Read the list of files according to its format with its file tree;
   - Verify that file compressed lengths and positions are consistent.
7. Read the **encrypted file zone** using its length;
8. Read the archive **signature** and verify it;
9. Verify that no extra bytes are appended to the archive.

Extraction is done by recursively decompressing files (using data from the **file name zone**), and writing them to the output folder.

## Configuration file

A configuration file can be specified in:
- `./faseal/faseal.conf` (UNIX targets)
- `"%USERPROFILE%\Documents\faseal\private` (Windows)

| Option                | Default value         | Description                              |
| --------------------- | --------------------- | ---------------------------------------- |
| `default-private-id`  | None                  | Path of the default private key          |
| `private-dir-path`    | `"~/.faseal/private/"` (UNIX targets) <br> `"%USERPROFILE%\Documents\faseal\private\"` (Windows) | Default folder for secret keys           |
| `public-dir-path`     | `"~/.faseal/public/"` (UNIX targets) <br> `"%USERPROFILE%\Documents\faseal\public\"` (Windows) | Default folder for public keys           |
| `compression-level`   | `9`                   | Brotli compression level for file chunks |
| `min-password-length` | `12`                  | Minimum password length                  |

The option and its values are separated by a `=`.

Example of configuration file:
```
main-private-path = "/path/to/NAME_95ff9626-e6e2-4df9-a758-3ba395b05042.fprv"
private-dir-path = "/path/to/private/"
public-dir-path = "/path/to/public/"
compression-level = 7
min-password-length = 16
```
