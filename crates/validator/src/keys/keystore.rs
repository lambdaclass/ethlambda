//! EIP-2335 keystore decryption.
//!
//! The format every staking tool emits: a JSON document holding a key-derivation
//! function (scrypt or pbkdf2), a checksum that verifies the password before any
//! decryption is attempted, and the secret under aes-128-ctr.

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::{EIP2335_KEYSTORE_VERSION, Error, Result};

#[derive(Debug, Deserialize)]
pub struct Keystore {
    /// The key-derivation, checksum and cipher parameters, plus the
    /// encrypted secret.
    pub crypto: Crypto,
    /// The validator's BLS public key, hex-encoded.
    pub pubkey: Option<String>,
    /// The keystore's HD derivation path (e.g. `m/12381/60/0/0`).
    ///
    /// ERC-2335 marks this required, but `decrypt` never reads it: refusing
    /// a keystore that would otherwise decrypt correctly would reject real
    /// operator key material over metadata this client has no use for.
    pub path: Option<String>,
    /// A UUID identifying this keystore.
    ///
    /// ERC-2335 marks this required too, but `decrypt` never reads it
    /// either, for the same reason `path` stays optional.
    pub uuid: Option<String>,
    /// The ERC-2335 schema version; only [`EIP2335_KEYSTORE_VERSION`] decrypts.
    pub version: u64,
    /// Where this keystore's JSON came from, used only to build error
    /// messages. Not part of the ERC-2335 schema: set by the constructor,
    /// never deserialized.
    #[serde(skip)]
    source: String,
}

#[derive(Debug, Deserialize)]
pub struct Crypto {
    /// The key-derivation function and its parameters.
    pub kdf: Kdf,
    /// The checksum that verifies the password before decryption runs.
    pub checksum: Checksum,
    /// The cipher that encrypts the secret, and its parameters.
    pub cipher: Cipher,
}

#[derive(Debug, Deserialize)]
pub struct Kdf {
    /// The key-derivation function's name: `scrypt` or `pbkdf2`.
    pub function: String,
    /// The function's parameters, shaped differently depending on `function`.
    pub params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct Checksum {
    /// The checksum function; only `sha256` is supported.
    pub function: String,
    /// The expected checksum, hex-encoded.
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct Cipher {
    /// The cipher function; only `aes-128-ctr` is supported.
    pub function: String,
    /// The cipher's parameters.
    pub params: CipherParams,
    /// The encrypted secret, hex-encoded.
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct CipherParams {
    /// The initialization vector, hex-encoded.
    pub iv: String,
}

impl Keystore {
    /// Parse a keystore from its JSON form.
    pub fn from_json(json: &str) -> Result<Self> {
        let mut keystore: Self = serde_json::from_str(json).map_err(|err| Error::Keystore {
            path: "<memory>".to_string(),
            reason: err.to_string(),
        })?;
        keystore.source = "<memory>".to_string();
        Ok(keystore)
    }

    /// Build a keystore error pointing at wherever this keystore's JSON came
    /// from, so a later file-loading constructor only has to change what it
    /// sets `source` to, not every call site that raises an error.
    fn keystore_error(&self, reason: impl Into<String>) -> Error {
        Error::Keystore {
            path: self.source.clone(),
            reason: reason.into(),
        }
    }

    /// Recover the 32-byte secret key, verifying the password first.
    ///
    /// The password check is deliberately a separate step ahead of decryption:
    /// the checksum tells us the password is right without the cipher ever
    /// running, which is what lets a wrong password be reported as such rather
    /// than as 32 bytes of garbage that only fail later at signing time.
    ///
    /// The result is wrapped in [`Zeroizing`] so the secret is scrubbed from
    /// memory on drop rather than lingering for the rest of the process.
    pub fn decrypt(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        if self.version != EIP2335_KEYSTORE_VERSION {
            return Err(Error::KeystoreVersion(self.version));
        }

        let password = normalize_password(password);
        let derived = self.derive_key(&password)?;

        let cipher_message = self.decode_hex(&self.crypto.cipher.message)?;
        if !self.checksum_matches(&derived, &cipher_message)? {
            return Err(Error::KeystoreBadPassword);
        }

        if self.crypto.cipher.function != "aes-128-ctr" {
            return Err(self.keystore_error(format!(
                "unsupported cipher {}",
                self.crypto.cipher.function
            )));
        }

        let iv = self.decode_hex(&self.crypto.cipher.params.iv)?;
        // Wrapped as soon as it holds the plaintext (post-decryption), so the
        // buffer is scrubbed on drop rather than left as an ordinary `Vec`.
        let mut secret = Zeroizing::new(cipher_message);
        self.apply_aes_128_ctr(&derived[..16], &iv, &mut secret)?;

        if secret.len() != 32 {
            return Err(
                self.keystore_error(format!("secret is {} bytes, expected 32", secret.len()))
            );
        }
        // Constructed before the copy rather than after: the secret is never
        // briefly held in a bare, unwrapped `[u8; 32]` on the stack between
        // being copied out of `secret` and getting a `Zeroizing` guarantee of
        // its own.
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&secret);
        Ok(out)
    }

    /// Run the keystore's KDF over the password, producing the 32-byte
    /// decryption key whose halves serve two different purposes: the first for
    /// the cipher, the second for the checksum.
    fn derive_key(&self, password: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params = &self.crypto.kdf.params;
        let salt = self.decode_hex(self.string_param(params, "salt")?)?;
        let dklen = self.u64_param(params, "dklen")? as usize;
        if dklen != 32 {
            return Err(self.keystore_error(format!("dklen is {dklen}, expected 32")));
        }

        let mut out = Zeroizing::new([0u8; 32]);
        match self.crypto.kdf.function.as_str() {
            "scrypt" => {
                let n = self.u64_param(params, "n")?;
                // RFC 7914 (which ERC-2335 references normatively) requires N
                // to be a power of two: it is scrypt's cost parameter,
                // expressed to the cipher as log2(N). A value that is not an
                // exact power of two would silently truncate through
                // `trailing_zeros`, deriving the wrong key and surfacing as a
                // bad-password error instead of the corrupt file it is.
                if n < 2 || !n.is_power_of_two() {
                    return Err(self
                        .keystore_error(format!("scrypt n must be a power of two >= 2, got {n}")));
                }
                let r = self.u64_param(params, "r")?;
                let r = u32::try_from(r)
                    .map_err(|_| self.keystore_error(format!("scrypt r={r} out of range")))?;
                let p = self.u64_param(params, "p")?;
                let p = u32::try_from(p)
                    .map_err(|_| self.keystore_error(format!("scrypt p={p} out of range")))?;
                // n was just verified to be an exact power of two, so this
                // recovers its exponent rather than truncating it.
                let log_n = n.trailing_zeros() as u8;
                let scrypt_params = scrypt::Params::new(log_n, r, p, 32)
                    .map_err(|err| self.keystore_error(format!("bad scrypt params: {err}")))?;
                scrypt::scrypt(password, &salt, &scrypt_params, out.as_mut())
                    .map_err(|err| self.keystore_error(format!("scrypt failed: {err}")))?;
            }
            "pbkdf2" => {
                let c = self.u64_param(params, "c")?;
                let c = u32::try_from(c)
                    .map_err(|_| self.keystore_error(format!("pbkdf2 c={c} out of range")))?;
                let prf = self.string_param(params, "prf")?;
                if prf != "hmac-sha256" {
                    return Err(self.keystore_error(format!("unsupported prf {prf}")));
                }
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, &salt, c, out.as_mut())
                    .map_err(|err| self.keystore_error(format!("pbkdf2 failed: {err}")))?;
            }
            other => {
                return Err(self.keystore_error(format!("unsupported kdf {other}")));
            }
        }
        Ok(out)
    }

    /// `sha256(derived_key[16..32] | cipher_message) == checksum.message`.
    fn checksum_matches(&self, derived: &[u8; 32], cipher_message: &[u8]) -> Result<bool> {
        if self.crypto.checksum.function != "sha256" {
            return Err(self.keystore_error(format!(
                "unsupported checksum {}",
                self.crypto.checksum.function
            )));
        }
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&derived[16..32]);
        hasher.update(cipher_message);
        let expected = self.decode_hex(&self.crypto.checksum.message)?;
        Ok(hasher.finalize().as_slice() == expected.as_slice())
    }

    fn apply_aes_128_ctr(&self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<()> {
        use aes::cipher::{KeyIvInit as _, StreamCipher as _};
        type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
        let mut cipher = Aes128Ctr::new_from_slices(key, iv)
            .map_err(|err| self.keystore_error(format!("bad aes key or iv: {err}")))?;
        cipher.apply_keystream(data);
        Ok(())
    }

    fn decode_hex(&self, value: &str) -> Result<Vec<u8>> {
        hex::decode(value.trim_start_matches("0x"))
            .map_err(|err| self.keystore_error(format!("bad hex: {err}")))
    }

    fn string_param<'a>(&self, params: &'a serde_json::Value, name: &str) -> Result<&'a str> {
        params
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| self.keystore_error(format!("missing kdf param {name}")))
    }

    fn u64_param(&self, params: &serde_json::Value, name: &str) -> Result<u64> {
        params
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| self.keystore_error(format!("missing kdf param {name}")))
    }
}

/// EIP-2335 requires NFKD normalization, then stripping the C0/C1 control
/// codes, then UTF-8 encoding, in that order. The control-code strip must
/// happen on Unicode scalar values, not on already-encoded bytes: a C1 code
/// point (U+0080-U+009F) is two bytes in UTF-8, and so is every other
/// character above U+007F, so a byte in that same numeric range can be an
/// unrelated character's continuation byte. Filtering post-encoding would
/// corrupt any such character instead of leaving it alone.
///
/// Wrapped in [`Zeroizing`] since this buffer holds the operator's password
/// in a form directly usable by the KDF.
fn normalize_password(password: &str) -> Zeroizing<Vec<u8>> {
    use unicode_normalization::UnicodeNormalization as _;
    Zeroizing::new(
        password
            .nfkd()
            .filter(|c| !(*c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(c)))
            .collect::<String>()
            .into_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The password from the EIP-2335 test vectors. Both keystores use it.
    const PASSWORD: &str = "\u{1d531}\u{1d522}\u{1d530}\u{1d531}\u{1d52d}\u{1d51e}\u{1d530}\u{1d530}\u{1d534}\u{1d52c}\u{1d52f}\u{1d521}\u{1f511}";

    /// The secret both test keystores encrypt.
    const SECRET: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    const SCRYPT: &str = r#"{
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32, "n": 262144, "p": 1, "r": 8,
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256", "params": {},
                "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": { "iv": "264daa3f303d7259501c93d997d84fe6" },
                "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
            }
        },
        "description": "This is a test keystore that uses scrypt to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/3141592653/589793238",
        "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
        "version": 4
    }"#;

    const PBKDF2: &str = r#"{
        "crypto": {
            "kdf": {
                "function": "pbkdf2",
                "params": {
                    "dklen": 32, "c": 262144, "prf": "hmac-sha256",
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256", "params": {},
                "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": { "iv": "264daa3f303d7259501c93d997d84fe6" },
                "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
            }
        },
        "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/0/0",
        "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
        "version": 4
    }"#;

    #[test]
    fn decrypts_the_scrypt_vector() {
        let keystore = Keystore::from_json(SCRYPT).expect("parses");
        let secret = keystore.decrypt(PASSWORD).expect("decrypts");
        assert_eq!(hex::encode(*secret), SECRET);
    }

    #[test]
    fn decrypts_the_pbkdf2_vector() {
        let keystore = Keystore::from_json(PBKDF2).expect("parses");
        let secret = keystore.decrypt(PASSWORD).expect("decrypts");
        assert_eq!(hex::encode(*secret), SECRET);
    }

    #[test]
    fn rejects_a_wrong_password_before_decrypting() {
        let keystore = Keystore::from_json(SCRYPT).expect("parses");
        let err = keystore
            .decrypt("not the password")
            .expect_err("must reject");
        assert!(matches!(err, Error::KeystoreBadPassword), "got {err:?}");
    }

    #[test]
    fn rejects_an_unsupported_version() {
        let json = SCRYPT.replace("\"version\": 4", "\"version\": 3");
        let keystore = Keystore::from_json(&json).expect("parses");
        let err = keystore.decrypt(PASSWORD).expect_err("must reject");
        assert!(matches!(err, Error::KeystoreVersion(3)), "got {err:?}");
    }

    #[test]
    fn rejects_a_non_power_of_two_scrypt_n() {
        let json = SCRYPT.replace("\"n\": 262144", "\"n\": 100000");
        let keystore = Keystore::from_json(&json).expect("parses");
        let err = keystore.decrypt(PASSWORD).expect_err("must reject");
        match &err {
            Error::Keystore { reason, .. } => {
                assert!(reason.contains("power of two"), "got {err:?}");
            }
            _ => panic!("got {err:?}"),
        }
    }

    #[test]
    fn rejects_an_unsupported_kdf_function() {
        let json = SCRYPT.replace("\"function\": \"scrypt\"", "\"function\": \"argon2\"");
        let keystore = Keystore::from_json(&json).expect("parses");
        let err = keystore.decrypt(PASSWORD).expect_err("must reject");
        match &err {
            Error::Keystore { reason, .. } => assert!(reason.contains("argon2"), "got {err:?}"),
            _ => panic!("got {err:?}"),
        }
    }

    #[test]
    fn rejects_an_unsupported_cipher_function() {
        let json = SCRYPT.replace(
            "\"function\": \"aes-128-ctr\"",
            "\"function\": \"aes-256-cbc\"",
        );
        let keystore = Keystore::from_json(&json).expect("parses");
        let err = keystore.decrypt(PASSWORD).expect_err("must reject");
        match &err {
            Error::Keystore { reason, .. } => {
                assert!(reason.contains("aes-256-cbc"), "got {err:?}")
            }
            _ => panic!("got {err:?}"),
        }
    }

    #[test]
    fn rejects_invalid_hex_in_salt() {
        let json = SCRYPT.replace(
            "\"salt\": \"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3\"",
            "\"salt\": \"not-hex\"",
        );
        let keystore = Keystore::from_json(&json).expect("parses");
        let err = keystore.decrypt(PASSWORD).expect_err("must reject");
        match &err {
            Error::Keystore { reason, .. } => assert!(reason.contains("bad hex"), "got {err:?}"),
            _ => panic!("got {err:?}"),
        }
    }
}
