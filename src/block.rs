//! Module contains items related to the input data block.

use std::array::TryFromSliceError;

/// Block length in bits.
pub const LENGTH_BITS: usize = 1024;
/// Block length in bytes.
pub const LENGTH_BYTES: usize = LENGTH_BITS / 8;
/// Block length in words (double bytes).
pub const LENGTH_WORDS: usize = LENGTH_BYTES / 2;
/// Block length in double words (quadruple bytes).
pub const LENGTH_DWORDS: usize = LENGTH_WORDS / 2;
/// Block length in quadruple words (octuple bytes).
pub const LENGTH_QWORDS: usize = LENGTH_DWORDS / 2;

pub(crate) struct Block([u8; LENGTH_BYTES]);

impl From<Block> for [u64; LENGTH_QWORDS] {
    fn from(Block(block): Block) -> Self {
        [
            u64::from_be_bytes([
                block[0x00],
                block[0x01],
                block[0x02],
                block[0x03],
                block[0x04],
                block[0x05],
                block[0x06],
                block[0x07],
            ]),
            u64::from_be_bytes([
                block[0x08],
                block[0x09],
                block[0x0A],
                block[0x0B],
                block[0x0C],
                block[0x0D],
                block[0x0E],
                block[0x0F],
            ]),
            u64::from_be_bytes([
                block[0x10],
                block[0x11],
                block[0x12],
                block[0x13],
                block[0x14],
                block[0x15],
                block[0x16],
                block[0x17],
            ]),
            u64::from_be_bytes([
                block[0x18],
                block[0x19],
                block[0x1A],
                block[0x1B],
                block[0x1C],
                block[0x1D],
                block[0x1E],
                block[0x1F],
            ]),
            u64::from_be_bytes([
                block[0x20],
                block[0x21],
                block[0x22],
                block[0x23],
                block[0x24],
                block[0x25],
                block[0x26],
                block[0x27],
            ]),
            u64::from_be_bytes([
                block[0x28],
                block[0x29],
                block[0x2A],
                block[0x2B],
                block[0x2C],
                block[0x2D],
                block[0x2E],
                block[0x2F],
            ]),
            u64::from_be_bytes([
                block[0x30],
                block[0x31],
                block[0x32],
                block[0x33],
                block[0x34],
                block[0x35],
                block[0x36],
                block[0x37],
            ]),
            u64::from_be_bytes([
                block[0x38],
                block[0x39],
                block[0x3A],
                block[0x3B],
                block[0x3C],
                block[0x3D],
                block[0x3E],
                block[0x3F],
            ]),
            u64::from_be_bytes([
                block[0x40],
                block[0x41],
                block[0x42],
                block[0x43],
                block[0x44],
                block[0x45],
                block[0x46],
                block[0x47],
            ]),
            u64::from_be_bytes([
                block[0x48],
                block[0x49],
                block[0x4A],
                block[0x4B],
                block[0x4C],
                block[0x4D],
                block[0x4E],
                block[0x4F],
            ]),
            u64::from_be_bytes([
                block[0x50],
                block[0x51],
                block[0x52],
                block[0x53],
                block[0x54],
                block[0x55],
                block[0x56],
                block[0x57],
            ]),
            u64::from_be_bytes([
                block[0x58],
                block[0x59],
                block[0x5A],
                block[0x5B],
                block[0x5C],
                block[0x5D],
                block[0x5E],
                block[0x5F],
            ]),
            u64::from_be_bytes([
                block[0x60],
                block[0x61],
                block[0x62],
                block[0x63],
                block[0x64],
                block[0x65],
                block[0x66],
                block[0x67],
            ]),
            u64::from_be_bytes([
                block[0x68],
                block[0x69],
                block[0x6A],
                block[0x6B],
                block[0x6C],
                block[0x6D],
                block[0x6E],
                block[0x6F],
            ]),
            u64::from_be_bytes([
                block[0x70],
                block[0x71],
                block[0x72],
                block[0x73],
                block[0x74],
                block[0x75],
                block[0x76],
                block[0x77],
            ]),
            u64::from_be_bytes([
                block[0x78],
                block[0x79],
                block[0x7A],
                block[0x7B],
                block[0x7C],
                block[0x7D],
                block[0x7E],
                block[0x7F],
            ]),
        ]
    }
}

impl TryFrom<&[u8]> for Block {
    type Error = TryFromSliceError;

    fn try_from(block: &[u8]) -> Result<Self, Self::Error> {
        block.try_into().map(Self)
    }
}
