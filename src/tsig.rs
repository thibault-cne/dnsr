use std::ffi::OsStr;
use std::io::Write;

use base64::Engine;
use domain::tsig::{Key, KeyName};

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
    let rng = ring::rand::SystemRandom::new();
    let name = name.try_into()?;

    let (key, secret) = Key::generate(domain::tsig::Algorithm::Sha512, &rng, name, None, None)?;
    let secret = base64::engine::general_purpose::STANDARD.encode(&secret);

    let mut file = std::fs::File::create(path)?;
    write!(file, "{}", secret)?;

    Ok(key)
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

    let secret = std::fs::read(path)?;
    let secret = base64::engine::general_purpose::STANDARD.decode(secret)?;

    Ok(Key::new(
        domain::tsig::Algorithm::Sha512,
        &secret,
        name.try_into()?,
        None,
        None,
    )?)
}
