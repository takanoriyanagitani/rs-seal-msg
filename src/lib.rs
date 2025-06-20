use std::io;

use io::Read;
use io::Write;

use std::fs::File;
use std::fs::Metadata;

use std::path::Path;

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

pub fn seal(a2g: &Aes256Gcm, nonce: &[u8], plain_msg: &[u8]) -> Result<Vec<u8>, io::Error> {
    a2g.encrypt(nonce.into(), plain_msg)
        .map_err(|_| "unable to seal the message")
        .map_err(io::Error::other)
}

pub fn open(
    a2g: &Aes256Gcm,
    nonce: &[u8],
    sealed: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, io::Error> {
    let mut combined: Vec<u8> = Vec::with_capacity(sealed.len() + tag.len());
    io::Write::write_all(&mut combined, sealed)?;
    io::Write::write_all(&mut combined, tag)?;
    let cs: &[u8] = &combined;
    a2g.decrypt(nonce.into(), cs)
        .map_err(|_| "unable to open the sealed message")
        .map_err(io::Error::other)
}

pub fn bytes2key(bytes: [u8; 32]) -> Aes256Gcm {
    let key = Key::<Aes256Gcm>::from_slice(&bytes);
    Aes256Gcm::new(key)
}

pub fn reader2key<R>(mut rdr: R) -> Result<Aes256Gcm, io::Error>
where
    R: Read,
{
    let mut buf: [u8; 32] = [0; 32];
    let s: &mut [u8] = &mut buf;
    rdr.read_exact(s)?;
    Ok(bytes2key(buf))
}

pub fn secret_file2key<P>(secret_file_path: P) -> Result<Aes256Gcm, io::Error>
where
    P: AsRef<Path>,
{
    let p: &Path = secret_file_path.as_ref();
    let f: File = File::open(p)?;
    reader2key(f)
}

pub struct SealedBox {
    pub nonce: [u8; NONCE_SIZE],
    pub sealed: Vec<u8>,
    pub tag: [u8; TAG_SIZE],
}

impl SealedBox {
    pub fn from_combined(combined: Vec<u8>) -> Result<Self, io::Error> {
        let min_size: usize = NONCE_SIZE + TAG_SIZE;
        let too_small: bool = combined.len() < min_size;
        let ok: bool = !too_small;
        ok.then_some(())
            .ok_or(io::Error::other("invalid sealed box"))?;
        let (nonce_s, others) = combined.split_at(NONCE_SIZE);
        let nonce_a: [u8; NONCE_SIZE] = nonce_s
            .try_into()
            .map_err(|_| "invalid nonce")
            .map_err(io::Error::other)?;
        let (ciphertext, tag_s) = others.split_at(others.len() - TAG_SIZE);
        let tag_a: [u8; TAG_SIZE] = tag_s
            .try_into()
            .map_err(|_| "invalid tag")
            .map_err(io::Error::other)?;

        Ok(Self {
            nonce: nonce_a,
            sealed: ciphertext.into(),
            tag: tag_a,
        })
    }

    pub fn from_file(mut file: File, limit: u64) -> Result<Self, io::Error> {
        let mut nonce: [u8; NONCE_SIZE] = [0; NONCE_SIZE];
        let mut tag: [u8; TAG_SIZE] = [0; TAG_SIZE];
        let meta: Metadata = file.metadata()?;
        let size: u64 = meta.len();
        let nt_size: u64 = (NONCE_SIZE + TAG_SIZE) as u64;
        let msg_size: u64 = size.saturating_sub(nt_size);
        if msg_size > limit {
            return Err(io::Error::other(format!("too big message: {msg_size}")));
        }

        file.read_exact(&mut nonce)?;
        let mut buf: Vec<u8> = vec![0; msg_size as usize];
        file.read_exact(&mut buf)?;
        file.read_exact(&mut tag)?;
        Ok(Self {
            nonce,
            sealed: buf,
            tag,
        })
    }

    pub fn from_reader<R>(rdr: R, limit: u64) -> Result<Self, io::Error>
    where
        R: Read,
    {
        let mut taken = rdr.take(limit);
        let mut buf: Vec<u8> = Vec::with_capacity(limit as usize);
        taken.read_to_end(&mut buf)?;
        Self::from_combined(buf)
    }

    pub fn from_filepath<P>(sealed_file_location: P, limit: u64) -> Result<Self, io::Error>
    where
        P: AsRef<Path>,
    {
        let p: &Path = sealed_file_location.as_ref();
        let f: File = File::open(p)?;
        Self::from_file(f, limit)
    }
}

impl SealedBox {
    pub fn to_message(&self, a2g: &Aes256Gcm) -> Result<Vec<u8>, io::Error> {
        open(a2g, &self.nonce, &self.sealed, &self.tag)
    }
}

pub fn file2sealed2msg2stdout<P>(
    key_filename: P,
    sealed_filename: P,
    sealed_size_max: u64,
) -> Result<(), io::Error>
where
    P: AsRef<Path>,
{
    let a2g: Aes256Gcm = secret_file2key(key_filename)?;
    let sealed: SealedBox = SealedBox::from_filepath(sealed_filename, sealed_size_max)?;
    let opened: Vec<u8> = sealed.to_message(&a2g)?;
    let o = io::stdout();
    let mut ol = o.lock();
    ol.write_all(&opened)?;
    ol.flush()
}

pub fn filename2msg<P>(msg_filename: P, max_size: u64) -> Result<Vec<u8>, io::Error>
where
    P: AsRef<Path>,
{
    let f: File = File::open(msg_filename)?;
    let mut taken = f.take(max_size);
    let mut buf: Vec<u8> = vec![];
    taken.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Writes the sealed message(nonce+ciphertext+tag) to the specified location.
pub fn file2msg2sealed2stdout<P>(
    key_filename: P,
    msg_filename: P,
    msg_size_max: u64,
) -> Result<(), io::Error>
where
    P: AsRef<Path>,
{
    let a2g: Aes256Gcm = secret_file2key(key_filename)?;

    let nonce: Nonce<_> = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce_s: &[u8] = nonce.as_slice();

    let msg: Vec<u8> = filename2msg(msg_filename, msg_size_max)?;

    let sealed: Vec<u8> = seal(&a2g, nonce_s, &msg)?;

    let o = io::stdout();
    let mut ol = o.lock();

    ol.write_all(nonce_s)?;
    ol.write_all(&sealed)?;

    ol.flush()
}
