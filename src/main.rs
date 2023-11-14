use clap::Parser;
use memmap2::Mmap;
use std::collections::HashSet;
use std::fs::{remove_file, File};
use std::io::{Error, ErrorKind};

mod archive;
mod cover;
mod crypto;
mod utils;

use crate::cover::*;

#[derive(Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
enum Args {
    #[command(name = "hide")]
    Hide {
        #[arg(required = true)]
        files: Vec<String>,

        #[arg(num_args = 1.., last = true, required = true)]
        output: Vec<String>,

        #[arg(short, long)]
        password: Option<String>,
    },

    #[command(name = "unhide")]
    Unhide {
        #[arg(required = true)]
        files: Vec<String>,

        #[arg(short, long, default_value = ".")]
        output: String,

        #[arg(short, long)]
        password: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args {
        Args::Hide {
            files,
            output,
            password,
        } => {
            hide(&files, &output, &password)?;
        }
        Args::Unhide {
            files,
            output,
            password,
        } => {
            unhide(&files, &output, &password)?;
        }
    }

    println!("Ok");

    Ok(())
}

fn err(msg: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err(Box::new(Error::new(ErrorKind::Other, msg)))
}

fn hide(
    input_files: &Vec<String>,
    cover_files: &Vec<String>,
    password: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if cover_files.len() > i16::MAX as usize {
        return err(&format!(
            "Cannot hide data inside {} files; the limit is {}",
            cover_files.len(),
            i16::MAX
        ));
    }

    // TODO: clean up the temp files if there is an error
    let mut payload_path = format!("{}.tmp", utils::get_temp_filename()?);
    archive::create(&payload_path, input_files)?;

    let mut encrypted = false;

    if let Some(pass) = password {
        encrypted = true;

        let encrypted_path = format!("{}.enc.tmp", utils::get_temp_filename()?);

        crypto::encrypt_file(&payload_path, &encrypted_path, pass)?;

        remove_file(&payload_path)?;
        payload_path = encrypted_path;
    }

    {
        let payload_file = File::open(&payload_path)?;
        let mut payload_file_slice = &(unsafe { Mmap::map(&payload_file)? }[..]);

        let part_size = payload_file_slice.len() / cover_files.len();
        let part_leftover = payload_file_slice.len() % cover_files.len();

        for i in 0..cover_files.len() {
            let cover = File::options()
                .read(true)
                .write(true)
                .open(&cover_files[i])?;

            let mut payload_size = part_size;

            // I love edge cases
            if i == cover_files.len() - 1 {
                payload_size += part_leftover;
            }

            let meta = Metadata::new()
                .with_payload_size(payload_size as u32)
                .with_encrypted(encrypted)
                .with_part(i as u16 + 1)
                .with_total_parts(cover_files.len() as u16);

            let (payload, remaining) = payload_file_slice.split_at(payload_size);

            // TODO: check if the file is actually a MZPE,
            // and use the appropriate cover type
            MZPECover::from(cover).cover(payload, &meta)?;

            payload_file_slice = remaining;
        }
    }

    remove_file(&payload_path)?;

    Ok(())
}

fn unhide(
    files: &Vec<String>,
    output_dir: &String,
    password: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if files.len() > i16::MAX as usize {
        return err(&format!(
            "Cannot unhide data from {} files; the limit is {}",
            files.len(),
            i16::MAX
        ));
    }

    let mut covers: Vec<(&String, MZPEUncover<File>)> = vec![];

    // Validate cover files
    for path in files.iter() {
        let file = File::open(path)?;

        let mut cover = MZPEUncover::from(file);

        if cover.parse().is_err() {
            return err(
                &format!(
                    "Failed to read metadata from {}\nThis file most likely doesn't have a payload hidden in it",
                    path
                ),
            );
        }

        covers.push((path, cover));
    }

    // Sort the cover files by the part number
    covers.sort_by(|a, b| return a.1.meta().unwrap().part().cmp(&b.1.meta().unwrap().part()));

    if utils::count_unique(&covers, |cover| cover.1.meta().unwrap().total_parts()) > 1 {
        return err(
            "The cover files don't match (total_parts is not the same for all files)\nThese files most likely don't hide anything together"
        );
    }

    if utils::count_unique(&covers, |cover| cover.1.meta().unwrap().encrypted()) > 1 {
        return err(
            "The cover files don't match (some files store encrypted data, others store normal data)\nThese files most likely don't hide anything together"
        );
    }

    let total_parts = covers[0].1.meta()?.total_parts();
    let encrypted = covers[0].1.meta()?.encrypted();

    if (covers.len() as u16) > total_parts {
        return err(&format!(
            "You passed too many cover files\nThere are {} total parts; you passed {}",
            total_parts,
            covers.len()
        ));
    }

    if (covers.len() as u16) < total_parts {
        let parts = covers
            .iter()
            .map(|cover| cover.1.meta().unwrap().part())
            .collect::<HashSet<_>>();

        let required_parts = HashSet::from_iter(1..=total_parts);

        let mut diff = required_parts
            .difference(&parts)
            .map(|part| part.to_string())
            .collect::<Vec<_>>();

        diff.sort();

        return err(&format!(
            "There are {} total parts; you seem to only have {}\nYou are missing these parts: {}",
            total_parts,
            covers.len(),
            diff.join(", ")
        ));
    }

    // Check if all required parts are present exactly once
    for i in 1..covers.len() {
        if covers[i - 1].1.meta().unwrap().part() != i as u16 {
            return err(
                "The cover files that you passed contain duplicated parts\nYou most likely passed the same file twice\nIf not, then these files hide entirely different payloads"
            );
        }
    }

    // Unhide all data
    let mut payload_path = utils::get_temp_filename()?;

    {
        let mut zip = File::create(&payload_path)?;

        for cover in covers.iter_mut() {
            if let Err(msg) = cover.1.uncover(&mut zip) {
                drop(zip);
                remove_file(payload_path)?;

                return err(&format!(
                    "Failed to unhide data from {}\n{}",
                    cover.0, // File path
                    msg
                ));
            }
        }
    }

    if encrypted {
        match password {
            Some(pass) => {
                let decrypted_path = format!("{}.dec.tmp", utils::get_temp_filename()?);

                crypto::decrypt_file(&payload_path, &decrypted_path, pass)?;

                remove_file(&payload_path)?;
                payload_path = decrypted_path;
            }
            None => {
                return err(
                    "The payload hidden in these files is encrypted\nPlease provide the password via the --password flag"
                );
            }
        }
    }

    archive::extract(&payload_path, output_dir)?;

    remove_file(&payload_path)?;

    Ok(())
}
