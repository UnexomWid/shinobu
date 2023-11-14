use std::fs::{create_dir_all, File};
use std::io::copy;
use std::path::Path;
use xz2::read::XzEncoder;
use xz2::write::XzDecoder;
use zip::{write::FileOptions, CompressionMethod, ZipArchive, ZipWriter};

pub fn create(path: &str, file_paths: &Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let zip = File::create(path)?;
    let mut writer = ZipWriter::new(zip);

    for file in file_paths {
        add_file_to_zip(&mut writer, file)?;
    }

    writer.finish()?;

    Ok(())
}

pub fn extract(path: &String, dir: &String) -> Result<(), Box<dyn std::error::Error>> {
    let zip_file = File::open(path)?;
    let mut zip = ZipArchive::new(zip_file)?;

    let dir_path = Path::new(dir);

    if !dir_path.exists() {
        create_dir_all(dir)?;
    }

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;

        println!("Extracting file {}", file.name());

        let out = Path::new(dir).join(file.name());
        let out = File::create(out.as_os_str())?;
        let mut decompressor = XzDecoder::new(out);

        copy(&mut file, &mut decompressor)?;
    }

    Ok(())
}

fn add_file_to_zip(
    zip_writer: &mut ZipWriter<File>,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Tell zip to store the bytes as-is; we'll manually compress them with xz2
    let opts = FileOptions::default().compression_method(CompressionMethod::Stored);

    let file = File::open(file_path)?;
    zip_writer.start_file(file_path, opts)?;

    // 6 = compression level
    let mut compressor = XzEncoder::new(file, 6);
    copy(&mut compressor, zip_writer)?;

    Ok(())
}
