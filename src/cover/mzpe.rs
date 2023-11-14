use std::io::prelude::*;
use std::io::{copy, Cursor, Error, ErrorKind, Read, SeekFrom, Write};
use std::mem::size_of;

use crate::cover::{Cover, Metadata, Uncover};

pub struct MZPECover<T: Read + Write + Seek> {
    inner: T,
}

impl<T: Read + Write + Seek> From<T> for MZPECover<T> {
    fn from(src: T) -> MZPECover<T> {
        MZPECover { inner: src }
    }
}

impl<T: Read + Write + Seek> Cover for MZPECover<T> {
    fn cover(&mut self, src: &[u8], meta: &Metadata) -> Result<(), Box<dyn std::error::Error>> {
        let mzpe_size = self.inner.seek(SeekFrom::End(0))?;

        if mzpe_size + src.len() as u64 > i32::MAX as u64 {
            return Err(Box::new(Error::new(
                ErrorKind::Other,
                "Cannot hide data without breaking the PE file\nPE files are limited to 2GB; Windows won't load files larger than that",
            )));
        }

        copy(&mut Cursor::new(&src), &mut self.inner)?;

        let metadata: u64 = (*meta).into();
        self.inner.write_all(&metadata.to_be_bytes())?;

        Ok(())
    }
}

pub struct MZPEUncover<T: Read + Seek> {
    inner: T,
    meta: Option<Metadata>,
}

impl<T: Read + Seek> From<T> for MZPEUncover<T> {
    fn from(val: T) -> MZPEUncover<T> {
        MZPEUncover {
            inner: val,
            meta: None,
        }
    }
}

impl<T: Read + Seek> Uncover for MZPEUncover<T> {
    fn uncover<W: Write>(&mut self, dest: &mut W) -> Result<(), Box<dyn std::error::Error>> {
        self.inner.seek(SeekFrom::End(
            -(size_of::<Metadata>() as i64) - self.meta.unwrap().payload_size() as i64,
        ))?;

        copy(
            &mut self
                .inner
                .by_ref()
                .take(self.meta.unwrap().payload_size() as u64),
            dest,
        )?;

        Ok(())
    }

    fn parse(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.inner
            .seek(SeekFrom::End(-(size_of::<Metadata>() as i64)))?;

        let mut meta = [0u8; 8];
        self.inner.read_exact(&mut meta)?;

        let meta = Metadata::from(u64::from_be_bytes(meta));

        if meta.part() == 0 || meta.total_parts() == 0 || meta.part() > meta.total_parts() {
            return Err(Box::new(Error::new(
                ErrorKind::Other,
                "Invalid payload metadata; this cover most likely doesn't have a hidden payload",
            )));
        }

        self.meta = Some(meta);

        Ok(())
    }

    fn meta(&self) -> Result<&Metadata, Box<dyn std::error::Error>> {
        self.meta.as_ref().ok_or(Box::new(Error::new(
            ErrorKind::Other,
            "No metadata available for this cover\nCall parse() before calling meta(), and make sure it doesn't return an error",
        )))
    }
}
