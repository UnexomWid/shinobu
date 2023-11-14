use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::io::{Error, ErrorKind};
use std::fs::File;
use memmap2::{Mmap, MmapMut};

pub fn encrypt_file(src: &String, dest: &String, pass: &String) -> Result<(), Box<dyn std::error::Error>> {
    let original = File::open(&src)?;
    let encrypted = File::options().read(true).write(true).create(true).open(&dest)?;

    let original_slice = &(unsafe { Mmap::map(&original)? }[..]);

    encrypted.set_len(get_encrypted_size(original_slice) as u64)?;

    let encrypted_slice = &mut (unsafe { MmapMut::map_mut(&encrypted)? }[..]);

    encrypt(original_slice, encrypted_slice, pass.as_bytes())?;

    Ok(())
}

pub fn decrypt_file(src: &String, dest: &String, pass: &String) -> Result<(), Box<dyn std::error::Error>> {
    let original = File::open(&src)?;
    let decrypted = File::options().read(true).write(true).create(true).open(&dest)?;

    let original_slice = &(unsafe { Mmap::map(&original)? }[..]);

    // The decrypted file can't be larger than the encrypted one,
    // so truncate the file based on that
    decrypted.set_len(original_slice.len() as u64)?;

    let mut decrypted_slice = unsafe { MmapMut::map_mut(&decrypted)? };
    let size = decrypt(original_slice, &mut decrypted_slice[..], pass.as_bytes())?;

    // The mapped section must be closed before truncating the file
    drop(decrypted_slice);

    // Re-truncate the file based on the original data size
    decrypted.set_len(size as u64)?;

    Ok(())
}

fn encrypt(src: &[u8], dest: &mut [u8], pass: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng: StdRng = SeedableRng::from_entropy();

    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];

    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    dest[..salt.len()].copy_from_slice(&salt);
    dest[salt.len()..salt.len() + iv.len()].copy_from_slice(&iv);

    let mut key = [0u8; 32];

    derive_key(&pass, &salt, &mut key).unwrap();

    let result = cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(src, &mut dest[salt.len() + iv.len()..]);

    if let Err(_) = result {
        return Err(Box::new(Error::new(
            ErrorKind::Other,
            format!("Failed to encrypt data with the provided password"),
        )));
    }

    Ok(())
}

fn decrypt(src: &[u8], dest: &mut [u8], pass: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    let (salt, src) = src.split_at(16);
    let (iv, src) = src.split_at(16);

    let mut key = [0u8; 32];

    derive_key(&pass, &salt, &mut key).unwrap();

    let result = cbc::Decryptor::<aes::Aes256>::new(&key.into(), iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(src, dest);

    match result {
        Err(_) => Err(Box::new(Error::new(
            ErrorKind::Other,
            format!("The password is invalid, or the data is corrupted"),
        ))),
        Ok(slice) => Ok(slice.len())
    }
}

fn get_encrypted_size(src: &[u8]) -> usize {
    // For AES with PKCS7, the size is:
    // - the nearest multiple of 16 rounded up, if the original size is not a multiple of 16
    // - size + 16 otherwise (due to an extra block of padding)
    let salt_and_iv_size = 32;

    return src.len() + (16 - src.len() % 16) + salt_and_iv_size;
}

fn derive_key(pass: &[u8], salt: &[u8], out: &mut [u8]) -> Result<(), argon2::Error> {
    // The crate defaults can change at any time, so set the params explicitly
    let argon2id = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            19_456, // m_cost
            2,      // t_cost
            1,      // p_cost
            Some(out.len()),
        )?,
    );

    argon2id.hash_password_into(pass, salt, out)?;

    Ok(())
}
