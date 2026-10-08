//! Allocation-free framing walker for the pinned LDK 0.2.2 writer. Not an LDK
//! deserializer: skipped payloads are intentionally not semantically validated.
use super::BackupError;

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
    pub(super) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    pub(super) fn finish(self) -> Result<(), BackupError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(BackupError::InvalidFormat)
        }
    }
    pub(super) fn take(&mut self, len: usize) -> Result<&'a [u8], BackupError> {
        let value = self.bytes.get(..len).ok_or(BackupError::InvalidFormat)?;
        self.bytes = &self.bytes[len..];
        Ok(value)
    }
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], BackupError> {
        self.take(N)?
            .try_into()
            .map_err(|_| BackupError::InvalidFormat)
    }
    pub(super) fn u8(&mut self) -> Result<u8, BackupError> {
        Ok(u8::from_be_bytes(self.array()?))
    }
    pub(super) fn u16(&mut self) -> Result<u16, BackupError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub(super) fn u32(&mut self) -> Result<u32, BackupError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(super) fn u64(&mut self) -> Result<u64, BackupError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(super) fn u48(&mut self) -> Result<u64, BackupError> {
        let mut bytes = [0; 8];
        bytes[2..].copy_from_slice(self.take(6)?);
        Ok(u64::from_be_bytes(bytes))
    }
    pub(super) fn boolean(&mut self) -> Result<bool, BackupError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(BackupError::InvalidFormat),
        }
    }
    pub(super) fn version(&mut self) -> Result<(), BackupError> {
        if self.take(2)? == [1, 1] {
            Ok(())
        } else {
            Err(BackupError::UnsupportedFormat)
        }
    }
    pub(super) fn field(&mut self) -> Result<&'a [u8], BackupError> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
    pub(super) fn bigsize(&mut self) -> Result<u64, BackupError> {
        let (value, min) = match self.u8()? {
            0xfd => (u64::from(self.u16()?), 0xfd),
            0xfe => (u64::from(self.u32()?), 0x10000),
            0xff => (self.u64()?, 0x100000000),
            n => (u64::from(n), 0),
        };
        if value < min {
            Err(BackupError::InvalidFormat)
        } else {
            Ok(value)
        }
    }
    fn length(value: u64) -> Result<usize, BackupError> {
        usize::try_from(value).map_err(|_| BackupError::LimitExceeded)
    }
    pub(super) fn tlv(&mut self) -> Result<&'a [u8], BackupError> {
        let len = Self::length(self.bigsize()?)?;
        self.take(len)
    }
    pub(super) fn option(&mut self) -> Result<(), BackupError> {
        let len = self.bigsize()?;
        if len != 0 {
            self.take(Self::length(len - 1)?)?;
        }
        Ok(())
    }
    // Every loop iteration consumes at least one byte. Counts cannot amplify
    // work beyond input length; payload skips are constant-time and borrow only.
    pub(super) fn count(&mut self) -> Result<usize, BackupError> {
        let count = Self::length(self.u64()?)?;
        if count > self.bytes.len() {
            Err(BackupError::InvalidFormat)
        } else {
            Ok(count)
        }
    }
    pub(super) fn skip_items(&mut self, count: usize, width: usize) -> Result<(), BackupError> {
        self.take(count.checked_mul(width).ok_or(BackupError::LimitExceeded)?)?;
        Ok(())
    }
    pub(super) fn event(&mut self) -> Result<(), BackupError> {
        match self.u8()? {
            // Pinned events written without payload. All others use TLV framing.
            0 | 17 | 35 | 45 | 47 | 49 => {}
            1 | 2 | 3 | 5 | 6 | 7 | 9 | 11 | 13 | 15 | 19 | 21 | 23 | 25 | 27 | 29 | 31 | 37
            | 39 | 41 | 43 | 50 | 52 => {
                self.tlv()?;
            }
            _ => return Err(BackupError::UnsupportedFormat),
        }
        Ok(())
    }
    fn package(&mut self) -> Result<(), BackupError> {
        for _ in 0..self.count()? {
            self.take(36)?; // Bitcoin outpoint
            if self.u8()? > 5 {
                return Err(BackupError::UnsupportedFormat);
            }
            self.tlv()?; // PackageSolvingData variant, never decode claim material
        }
        self.tlv()?;
        Ok(())
    }
    pub(super) fn onchain_handler(&mut self) -> Result<(), BackupError> {
        // write() in vendor/lightning/src/chain/onchaintx.rs, version 1.
        self.version()?;
        self.field()?;
        self.tlv()?; // holder commitment

        // Pinned writer emits None for the obsolete HTLC signature caches.
        if self.u8()? != 0 {
            return Err(BackupError::UnsupportedFormat);
        }
        self.option()?; // previous holder commitment
        if self.u8()? != 0 {
            return Err(BackupError::UnsupportedFormat);
        }
        self.tlv()?; // channel parameters
        let signer_len = self.u32()? as usize;
        self.take(signer_len)?;
        for _ in 0..self.count()? {
            self.take(32)?;
            self.package()?;
        }
        let count = self.count()?;
        self.skip_items(count, 36 + 32 + 4)?;
        for _ in 0..self.count()? {
            self.take(4)?;
            for _ in 0..self.count()? {
                self.package()?;
            }
        }
        for _ in 0..self.count()? {
            self.tlv()?;
        }
        self.tlv()?;
        Ok(())
    }
}
