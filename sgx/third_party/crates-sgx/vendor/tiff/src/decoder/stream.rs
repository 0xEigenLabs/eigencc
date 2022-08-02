//! All IO functionality needed for TIFF decoding

use crate::error::{TiffError, TiffResult};
use std::prelude::v1::*;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use lzw;
use miniz_oxide::inflate;
use std::io::{self, Read, Seek};

/// Byte order of the TIFF file.
#[derive(Clone, Copy, Debug)]
pub enum ByteOrder {
    /// little endian byte order
    LittleEndian,
    /// big endian byte order
    BigEndian,
}

/// Reader that is aware of the byte order.
pub trait EndianReader: Read {
    /// Byte order that should be adhered to
    fn byte_order(&self) -> ByteOrder;

    /// Reads an u16
    #[inline(always)]
    fn read_u16(&mut self) -> Result<u16, io::Error> {
        match self.byte_order() {
            ByteOrder::LittleEndian => <Self as ReadBytesExt>::read_u16::<LittleEndian>(self),
            ByteOrder::BigEndian => <Self as ReadBytesExt>::read_u16::<BigEndian>(self),
        }
    }

    #[inline(always)]
    fn read_u16_into(&mut self, buffer: &mut [u16]) -> Result<(), io::Error> {
        match self.byte_order() {
            ByteOrder::LittleEndian => {
                <Self as ReadBytesExt>::read_u16_into::<LittleEndian>(self, buffer)
            }
            ByteOrder::BigEndian => {
                <Self as ReadBytesExt>::read_u16_into::<BigEndian>(self, buffer)
            }
        }
    }

    /// Reads an i16
    #[inline(always)]
    fn read_i16(&mut self) -> Result<i16, io::Error> {
        match self.byte_order() {
            ByteOrder::LittleEndian => <Self as ReadBytesExt>::read_i16::<LittleEndian>(self),
            ByteOrder::BigEndian => <Self as ReadBytesExt>::read_i16::<BigEndian>(self),
        }
    }

    /// Reads an u32
    #[inline(always)]
    fn read_u32(&mut self) -> Result<u32, io::Error> {
        match self.byte_order() {
            ByteOrder::LittleEndian => <Self as ReadBytesExt>::read_u32::<LittleEndian>(self),
            ByteOrder::BigEndian => <Self as ReadBytesExt>::read_u32::<BigEndian>(self),
        }
    }

    /// Reads an i32
    #[inline(always)]
    fn read_i32(&mut self) -> Result<i32, io::Error> {
        match self.byte_order() {
            ByteOrder::LittleEndian => <Self as ReadBytesExt>::read_i32::<LittleEndian>(self),
            ByteOrder::BigEndian => <Self as ReadBytesExt>::read_i32::<BigEndian>(self),
        }
    }
}

/// Reader that decompresses DEFLATE streams
pub struct DeflateReader {
    buffer: io::Cursor<Vec<u8>>,
    byte_order: ByteOrder,
}

impl DeflateReader {
    pub fn new<R: Read + Seek>(
        reader: &mut SmartReader<R>,
        max_uncompressed_length: usize,
    ) -> TiffResult<(usize, Self)> {
        let byte_order = reader.byte_order;
        let mut compressed = Vec::new();
        reader.read_to_end(&mut compressed)?;

        // TODO: Implement streaming compression, and remove this (temporary) and somewhat
        // misleading workaround.
        if compressed.len() > max_uncompressed_length {
            return Err(TiffError::LimitsExceeded);
        }

        let uncompressed =
            inflate::decompress_to_vec_zlib(&compressed).map_err(TiffError::from_inflate_status)?;

        Ok((
            uncompressed.len(),
            Self {
                byte_order,
                buffer: io::Cursor::new(uncompressed),
            },
        ))
    }
}

impl Read for DeflateReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.buffer.read(buf)
    }
}

impl EndianReader for DeflateReader {
    fn byte_order(&self) -> ByteOrder {
        self.byte_order
    }
}

/// Reader that decompresses LZW streams
pub struct LZWReader {
    buffer: io::Cursor<Vec<u8>>,
    byte_order: ByteOrder,
}

impl LZWReader {
    /// Wraps a reader
    pub fn new<R>(
        reader: &mut SmartReader<R>,
        compressed_length: usize,
        max_uncompressed_length: usize,
    ) -> io::Result<(usize, LZWReader)>
    where
        R: Read + Seek,
    {
        let order = reader.byte_order;
        let mut compressed = vec![0; compressed_length as usize];
        reader.read_exact(&mut compressed[..])?;
        let mut uncompressed = Vec::with_capacity(max_uncompressed_length);
        let mut decoder = lzw::DecoderEarlyChange::new(lzw::MsbReader::new(), 8);
        let mut bytes_read = 0;
        while bytes_read < compressed_length && uncompressed.len() < max_uncompressed_length {
            let (len, bytes) = decoder.decode_bytes(&compressed[bytes_read..])?;
            bytes_read += len;
            uncompressed.extend_from_slice(bytes);
        }

        let bytes = uncompressed.len();
        Ok((
            bytes,
            LZWReader {
                buffer: io::Cursor::new(uncompressed),
                byte_order: order,
            },
        ))
    }
}

impl Read for LZWReader {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.buffer.read(buf)
    }
}

impl EndianReader for LZWReader {
    #[inline(always)]
    fn byte_order(&self) -> ByteOrder {
        self.byte_order
    }
}

/// Reader that unpacks Apple's `PackBits` format
pub struct PackBitsReader {
    buffer: io::Cursor<Vec<u8>>,
    byte_order: ByteOrder,
}

impl PackBitsReader {
    /// Wraps a reader
    pub fn new<R: Read + Seek>(
        mut reader: R,
        byte_order: ByteOrder,
        length: usize,
    ) -> io::Result<(usize, PackBitsReader)> {
        let mut buffer = Vec::new();
        let mut read: usize = 0;
        while read < length {
            let lread = read_packbits_run(&mut reader, &mut buffer)?;
            if lread == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            read += lread;
        }
        Ok((
            buffer.len(),
            PackBitsReader {
                buffer: io::Cursor::new(buffer),
                byte_order,
            },
        ))
    }
}

fn read_packbits_run<R: Read + Seek>(reader: &mut R, buffer: &mut Vec<u8>) -> io::Result<usize> {
    let mut header: [u8; 1] = [0];

    let bytes = reader.read(&mut header)?;

    match bytes {
        0 => Ok(0),
        _ => match header[0] as i8 {
            -128 => Ok(1),
            h if h >= -127 && h <= -1 => {
                let new_len = buffer.len() + (1 - h as isize) as usize;
                reader.read_exact(&mut header)?;
                buffer.resize(new_len, header[0]);
                Ok(2)
            }
            h => {
                let num_vals = h as usize + 1;
                let start = buffer.len();
                buffer.resize(start + num_vals, 0);
                reader.read_exact(&mut buffer[start..])?;
                Ok(num_vals + 1)
            }
        },
    }
}

impl Read for PackBitsReader {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.buffer.read(buf)
    }
}

impl EndianReader for PackBitsReader {
    #[inline(always)]
    fn byte_order(&self) -> ByteOrder {
        self.byte_order
    }
}

/// Reader that is aware of the byte order.
#[derive(Debug)]
pub struct SmartReader<R>
where
    R: Read + Seek,
{
    reader: R,
    pub byte_order: ByteOrder,
}

impl<R> SmartReader<R>
where
    R: Read + Seek,
{
    /// Wraps a reader
    pub fn wrap(reader: R, byte_order: ByteOrder) -> SmartReader<R> {
        SmartReader { reader, byte_order }
    }
}

impl<R> EndianReader for SmartReader<R>
where
    R: Read + Seek,
{
    #[inline(always)]
    fn byte_order(&self) -> ByteOrder {
        self.byte_order
    }
}

impl<R: Read + Seek> Read for SmartReader<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R: Read + Seek> Seek for SmartReader<R> {
    #[inline]
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.reader.seek(pos)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_packbits() {
        let encoded = vec![
            0xFE, 0xAA, 0x02, 0x80, 0x00, 0x2A, 0xFD, 0xAA, 0x03, 0x80, 0x00, 0x2A, 0x22, 0xF7,
            0xAA,
        ];
        let encoded_len = encoded.len();

        let buff = io::Cursor::new(encoded);
        let (_, mut decoder) =
            PackBitsReader::new(buff, ByteOrder::LittleEndian, encoded_len).unwrap();

        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();

        let expected = vec![
            0xAA, 0xAA, 0xAA, 0x80, 0x00, 0x2A, 0xAA, 0xAA, 0xAA, 0xAA, 0x80, 0x00, 0x2A, 0x22,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        ];
        assert_eq!(decoded, expected);
    }
}
