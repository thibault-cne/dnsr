use std::ffi::OsStr;
use std::io::Write;

use bytes::BytesMut;
use domain::tsig::{Key, KeyName};
use ring::hkdf::KeyType;
use ring::rand::SecureRandom;

use crate::error;
use crate::error::Result;

pub fn delete_tsig<P>(fpath: &P) -> Result<()>
where
    P: AsRef<OsStr>,
{
    let path = std::path::Path::new(fpath);

    if path.is_file() {
        std::fs::remove_file(path)?;
    }

    Ok(())
}

pub fn generate_new_tsig<P, N>(fpath: &P, name: N) -> Result<Key>
where
    P: AsRef<OsStr>,
    N: TryInto<KeyName, Error = error::Error>,
{
    let path = std::path::Path::new(fpath);

    // Check if a file already exists at this path if so we return an error
    if path.is_file() {
        return Err(
            error!(TSIGFileAlreadyExist => "TSIG file at path ({}) already exits", fpath.as_ref().to_string_lossy()),
        );
    }

    // Generate the TSIG key
    let algorithm = ring::hmac::HMAC_SHA512;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = BytesMut::with_capacity(algorithm.len());
    bytes.resize(algorithm.len(), 0);
    rng.fill(&mut bytes)?;

    let hex_len = base16ct::encoded_len(&bytes);
    let mut key = vec![0u8; hex_len];
    base16ct::lower::encode(&bytes, &mut key)?;

    let mut file = std::fs::File::create(path)?;
    file.write_all(&key)?;

    Ok(Key::new(
        domain::tsig::Algorithm::Sha512,
        &bytes,
        name.try_into()?,
        None,
        None,
    )?)
}

pub fn load_tsig<P, N>(fpath: &P, name: N) -> Result<Key>
where
    P: AsRef<OsStr>,
    N: TryInto<KeyName, Error = error::Error>,
{
    let path = std::path::Path::new(fpath);

    if !path.is_file() {
        return Err(
            error!(TSIGFileNotFound => "TSIG file at path ({}) not found", fpath.as_ref().to_string_lossy()),
        );
    }

    let key = std::fs::read(path)?;

    Ok(Key::new(
        domain::tsig::Algorithm::Sha512,
        &key,
        name.try_into()?,
        None,
        None,
    )?)
}
