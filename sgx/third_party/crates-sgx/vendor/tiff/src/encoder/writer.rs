use error::TiffResult;
use byteorder::{BigEndian, ByteOrder, LittleEndian, NativeEndian, WriteBytesExt};
use std::io::{self, Seek, SeekFrom, Write};

pub trait TiffByteOrder: ByteOrder {
    fn write_header<W: Write>(writer: &mut TiffWriter<W>) -> TiffResult<()>;
}

impl TiffByteOrder for LittleEndian {
    fn write_header<W: Write>(writer: &mut TiffWriter<W>) -> TiffResult<()> {
        writer.writer.write_u16::<LittleEndian>(0x4949)?;
        writer.writer.write_u16::<LittleEndian>(42)?;
        writer.offset += 4;

        Ok(())
    }
}

impl TiffByteOrder for BigEndian {
    fn write_header<W: Write>(writer: &mut TiffWriter<W>) -> TiffResult<()> {
        writer.writer.write_u16::<BigEndian>(0x4d4d)?;
        writer.writer.write_u16::<BigEndian>(42)?;
        writer.offset += 4;

        Ok(())
    }
}

pub struct TiffWriter<W> {
    writer: W,
    offset: u64,
}

impl<W: Write> TiffWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer, offset: 0 }
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), io::Error> {
        self.writer.write_all(bytes)?;
        self.offset += bytes.len() as u64;
        Ok(())
    }

    pub fn write_u8(&mut self, n: u8) -> Result<(), io::Error> {
        self.writer.write_u8(n)?;
        self.offset += 1;
        Ok(())
    }

    pub fn write_i8(&mut self, n: i8) -> Result<(), io::Error> {
        self.writer.write_i8(n)?;
        self.offset += 1;
        Ok(())
    }

    pub fn write_u16(&mut self, n: u16) -> Result<(), io::Error> {
        self.writer.write_u16::<NativeEndian>(n)?;
        self.offset += 2;

        Ok(())
    }

    pub fn write_i16(&mut self, n: i16) -> Result<(), io::Error> {
        self.writer.write_i16::<NativeEndian>(n)?;
        self.offset += 2;

        Ok(())
    }

    pub fn write_u32(&mut self, n: u32) -> Result<(), io::Error> {
        self.writer.write_u32::<NativeEndian>(n)?;
        self.offset += 4;

        Ok(())
    }

    pub fn write_i32(&mut self, n: i32) -> Result<(), io::Error> {
        self.writer.write_i32::<NativeEndian>(n)?;
        self.offset += 4;

        Ok(())
    }

    pub fn write_u64(&mut self, n: u64) -> Result<(), io::Error> {
        self.writer.write_u64::<NativeEndian>(n)?;
        self.offset += 8;

        Ok(())
    }

    pub fn pad_word_boundary(&mut self) -> Result<(), io::Error> {
        if self.offset % 4 != 0 {
            let padding = [0, 0, 0];
            let padd_len = 4 - (self.offset % 4);
            self.writer.write_all(&padding[..padd_len as usize])?;
            self.offset += padd_len;
        }

        Ok(())
    }
}

impl<W: Seek> TiffWriter<W> {
    pub fn goto_offset(&mut self, offset: u64) -> Result<(), io::Error> {
        self.offset = offset;
        self.writer.seek(SeekFrom::Start(offset as u64))?;
        Ok(())
    }
}
