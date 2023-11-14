use bitfield_struct::*;
use std::io::Write;

mod mzpe;
pub use mzpe::{MZPECover, MZPEUncover};

#[bitfield(u64, order=Msb)]
pub struct Metadata {
    #[bits(32)]
    pub payload_size: u32,

    #[bits(1)]
    pub encrypted: bool,
    #[bits(15)]
    pub part: u16,

    #[bits(1, default = false)]
    reserved: bool,
    #[bits(15)]
    pub total_parts: u16,
}

pub trait Cover {
    /// Hide the specified payload inside this cover, along with the provided metadata
    fn cover(&mut self, src: &[u8], meta: &Metadata) -> Result<(), Box<dyn std::error::Error>>;
}

pub trait Uncover {
    /// Extract the payload hidden in this cover to the specified destination
    fn uncover<W: Write>(&mut self, dest: &mut W) -> Result<(), Box<dyn std::error::Error>>;

    /// Parse the cover and check if the payload metadata is valid
    fn parse(&mut self) -> Result<(), Box<dyn std::error::Error>>;

    /// Get the metadata for the payload hidden in this cover
    /// parse() must be called before this
    fn meta(&self) -> Result<&Metadata, Box<dyn std::error::Error>>;
}
