//! This crate provides an implementation of the SHA-2 512 hash function based on [FIPS PUB 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
//!
//! # Setup
//!
//! To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:
//!
//! ```toml
//! [dependencies]
//! chksum-hash-sha2-512 = "0.0.0"
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```sh
//! cargo add chksum-hash-sha2-512
//! ```     
//!
//! # Batch Processing
//!
//! The digest of known-size data can be calculated with the [`hash`] function.
//!
//! ```rust
//! use chksum_hash_sha2_512 as sha2_512;
//!
//! let digest = sha2_512::hash("example data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "ed59c5759a9ece516cec0c0623142d0e9fe70a27d750eee7fd38f4550d50addd873d0fa1a51fc823c1e3d5cada203f4a05d8325caacb7d3e0727a701f3f07e5f"
//! );
//! ```
//!
//! # Stream Processing
//!
//! The digest of data streams can be calculated chunk-by-chunk with a consumer created by calling the [`default`] function.
//!
//! ```rust
//! // Import all necessary items
//! # use std::io;
//! # use std::path::PathBuf;
//! use std::fs::File;
//! use std::io::Read;
//!
//! use chksum_hash_sha2_512 as sha2_512;
//!
//! # fn wrapper(path: PathBuf) -> io::Result<()> {
//! // Create a hash instance
//! let mut hash = sha2_512::default();
//!
//! // Open a file and create a buffer for incoming data
//! let mut file = File::open(path)?;
//! let mut buffer = vec![0; 64];
//!
//! // Iterate chunk by chunk
//! while let Ok(count) = file.read(&mut buffer) {
//!     // EOF reached, exit loop
//!     if count == 0 {
//!         break;
//!     }
//!
//!     // Update the hash with data
//!     hash.update(&buffer[..count]);
//! }
//!
//! // Calculate the digest
//! let digest = hash.digest();
//! // Cast the digest to hex and compare
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "ed59c5759a9ece516cec0c0623142d0e9fe70a27d750eee7fd38f4550d50addd873d0fa1a51fc823c1e3d5cada203f4a05d8325caacb7d3e0727a701f3f07e5f"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # Internal Buffering
//!
//! An internal buffer is utilized due to the unknown size of data chunks.
//!
//! The size of this buffer is at least as large as one hash block of data processed at a time.
//!
//! To mitigate buffering-related performance issues, ensure the length of processed chunks is a multiple of the block size.
//!
//! # Input Type
//!
//! Anything that implements `AsRef<[u8]>` can be passed as input.
//!
//! ```rust
//! use chksum_hash_sha2_512 as sha2_512;
//!
//! let digest = sha2_512::default()
//!     .update("str")
//!     .update(b"bytes")
//!     .update([0x75, 0x38])
//!     .digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "46a700a6419da55a9375a63860f441134370cc83ede59e7af64a7edbbaadfbb1132a39d0bffce951b9296b5333797e5ad62e1b03469999b4e6b005a3fb49ea98"
//! );
//! ```
//!
//! Since [`Digest`] implements `AsRef<[u8]>`, digests can be chained to calculate hash of a hash digest.
//!
//! ```rust
//! use chksum_hash_sha2_512 as sha2_512;
//!
//! let digest = sha2_512::hash(b"example data");
//! let digest = sha2_512::hash(digest);
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "e2248c7fd6a042f5e6e006a05cb7c254f3bd2f385d06c541cf763ffd98344d241d014aafe7b1c33ab7660977ab7440b9d83a4be793988cb9df24f70619766982"
//! );
//! ```
//!
//! # License
//!
//! This crate is licensed under the MIT License.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]

pub mod block;
pub mod digest;
pub mod state;

use chksum_hash_core as core;

use crate::block::Block;
#[doc(inline)]
pub use crate::block::LENGTH_BYTES as BLOCK_LENGTH_BYTES;
#[doc(inline)]
pub use crate::digest::{Digest, LENGTH_BYTES as DIGEST_LENGTH_BYTES};
#[doc(inline)]
pub use crate::state::State;

/// Creates a new hash.
///
/// # Example
///
/// ```rust
/// use chksum_hash_sha2_512 as sha2_512;
///
/// let digest = sha2_512::new().digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
/// );
///
/// let digest = sha2_512::new().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
/// );
/// ```
#[must_use]
pub fn new() -> Update {
    Update::new()
}

/// Creates a default hash.
///
/// # Example
///
/// ```rust
/// use chksum_hash_sha2_512 as sha2_512;
///
/// let digest = sha2_512::default().digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
/// );
///
/// let digest = sha2_512::default().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
/// );
/// ```
#[must_use]
pub fn default() -> Update {
    core::default()
}

/// Computes the hash of the given input.
///
/// # Example
///
/// ```rust
/// use chksum_hash_sha2_512 as sha2_512;
///
/// let digest = sha2_512::hash("data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
/// );
/// ```
pub fn hash(data: impl AsRef<[u8]>) -> Digest {
    core::hash::<Update>(data)
}

/// A hash state containing an internal buffer that can handle an unknown amount of input data.
///
/// # Example
///
/// ```rust
/// use chksum_hash_sha2_512 as sha2_512;
///
/// // Create a new hash instance
/// let mut hash = sha2_512::Update::new();
///
/// // Fill with data
/// hash.update("data");
///
/// // Finalize and create a digest
/// let digest = hash.finalize().digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
/// );
///
/// // Reset to default values
/// hash.reset();
///
/// // Produce a hash digest using internal finalization
/// let digest = hash.digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
/// );
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct Update {
    state: State,
    unprocessed: Vec<u8>,
    processed: usize,
}

impl Update {
    /// Creates a new hash.
    #[must_use]
    pub fn new() -> Self {
        let state = state::new();
        let unprocessed = Vec::with_capacity(BLOCK_LENGTH_BYTES);
        let processed = 0;
        Self {
            state,
            unprocessed,
            processed,
        }
    }

    /// Updates the internal state with an input data.
    ///
    /// # Performance issues
    ///
    /// To achieve maximum performance, the length of incoming data parts should be a multiple of the block length.
    ///
    /// In any other case, an internal buffer is used, which can cause a speed decrease in performance.
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> &mut Self {
        let data = data.as_ref();

        if self.unprocessed.is_empty() {
            // Internal buffer is empty, incoming data can be processed without buffering.
            let mut chunks = data.chunks_exact(BLOCK_LENGTH_BYTES);
            for chunk in chunks.by_ref() {
                let block = Block::try_from(chunk)
                    .expect("chunk length must be exact size as block")
                    .into();
                self.state = self.state.update(block);
                self.processed = self.processed.wrapping_add(BLOCK_LENGTH_BYTES);
            }
            let remainder = chunks.remainder();
            if !remainder.is_empty() {
                self.unprocessed.extend(remainder);
            }
        } else if (self.unprocessed.len() + data.len()) < BLOCK_LENGTH_BYTES {
            // Not enough data even for one block.
            self.unprocessed.extend(data);
        } else {
            // Create the first block from the buffer, create the second (and every other) block from incoming data.
            assert!(
                self.unprocessed.len() < BLOCK_LENGTH_BYTES,
                "unprocessed must contain less data than one block"
            );
            let missing = BLOCK_LENGTH_BYTES - self.unprocessed.len();
            assert!(
                missing <= data.len(),
                "data length must be greater than or equal to the missing block size"
            );
            let (fillment, data) = data.split_at(missing);
            let block = {
                let mut block = [0u8; BLOCK_LENGTH_BYTES];
                let (first_part, second_part) = block.split_at_mut(self.unprocessed.len());
                first_part.copy_from_slice(self.unprocessed.drain(..self.unprocessed.len()).as_slice());
                second_part[..missing].copy_from_slice(fillment);
                block
            };
            let mut chunks = block.chunks_exact(BLOCK_LENGTH_BYTES);
            for chunk in chunks.by_ref() {
                let block = Block::try_from(chunk)
                    .expect("chunk length must be exact size as block")
                    .into();
                self.state = self.state.update(block);
                self.processed = self.processed.wrapping_add(BLOCK_LENGTH_BYTES);
            }
            let remainder = chunks.remainder();
            assert!(remainder.is_empty(), "chunks remainder must be empty");

            let mut chunks = data.chunks_exact(BLOCK_LENGTH_BYTES);
            for chunk in chunks.by_ref() {
                let block = Block::try_from(chunk)
                    .expect("chunk length must be exact size as block")
                    .into();
                self.state = self.state.update(block);
                self.processed = self.processed.wrapping_add(BLOCK_LENGTH_BYTES);
            }
            let remainder = chunks.remainder();
            self.unprocessed.extend(remainder);
        }

        self
    }

    /// Applies padding and produces the finalized state.
    #[must_use]
    pub fn finalize(&self) -> Finalize {
        let mut state = self.state;

        assert!(
            self.unprocessed.len() < BLOCK_LENGTH_BYTES,
            "unprocessed data length must be less than block length"
        );

        let length = {
            let length = (self.unprocessed.len() + self.processed) as u128;
            let length = length * 8; // convert byte-length into bits-length
            length.to_be_bytes()
        };

        if (self.unprocessed.len() + 1 + length.len()) <= BLOCK_LENGTH_BYTES {
            let padding = {
                let mut padding = [0u8; BLOCK_LENGTH_BYTES];
                padding[..self.unprocessed.len()].copy_from_slice(&self.unprocessed[..self.unprocessed.len()]);
                padding[self.unprocessed.len()] = 0x80;
                padding[(BLOCK_LENGTH_BYTES - length.len())..].copy_from_slice(&length);
                padding
            };

            let block = {
                let block = &padding[..];
                Block::try_from(block)
                    .expect("padding length must exact size as block")
                    .into()
            };
            state = state.update(block);
        } else {
            let padding = {
                let mut padding = [0u8; BLOCK_LENGTH_BYTES * 2];
                padding[..self.unprocessed.len()].copy_from_slice(&self.unprocessed[..self.unprocessed.len()]);
                padding[self.unprocessed.len()] = 0x80;
                padding[(BLOCK_LENGTH_BYTES * 2 - length.len())..].copy_from_slice(&length);
                padding
            };

            let block = {
                let block = &padding[..BLOCK_LENGTH_BYTES];
                Block::try_from(block)
                    .expect("padding length must exact size as block")
                    .into()
            };
            state = state.update(block);

            let block = {
                let block = &padding[BLOCK_LENGTH_BYTES..];
                Block::try_from(block)
                    .expect("padding length must exact size as block")
                    .into()
            };
            state = state.update(block);
        }

        Finalize { state }
    }

    /// Resets the internal state to default values.
    pub fn reset(&mut self) -> &mut Self {
        self.state = self.state.reset();
        self.unprocessed.clear();
        self.processed = 0;
        self
    }

    /// Produces the hash digest using internal finalization.
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.finalize().digest()
    }
}

impl core::Update for Update {
    type Digest = Digest;
    type Finalize = Finalize;

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.update(data);
    }

    fn finalize(&self) -> Self::Finalize {
        self.finalize()
    }

    fn reset(&mut self) {
        self.reset();
    }
}

impl Default for Update {
    fn default() -> Self {
        Self::new()
    }
}

/// A finalized hash state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Finalize {
    state: State,
}

impl Finalize {
    /// Creates and returns the hash digest.
    #[must_use]
    #[rustfmt::skip]
    pub fn digest(&self) -> Digest {
        let State { a, b, c, d, e, f, g, h } = self.state;
        let [a, b, c, d, e, f, g, h] = [
            a.to_be_bytes(),
            b.to_be_bytes(),
            c.to_be_bytes(),
            d.to_be_bytes(),
            e.to_be_bytes(),
            f.to_be_bytes(),
            g.to_be_bytes(),
            h.to_be_bytes(),
        ];
        Digest::new([
            a[0], a[1], a[2], a[3],
            a[4], a[5], a[6], a[7],
            b[0], b[1], b[2], b[3],
            b[4], b[5], b[6], b[7],
            c[0], c[1], c[2], c[3],
            c[4], c[5], c[6], c[7],
            d[0], d[1], d[2], d[3],
            d[4], d[5], d[6], d[7],
            e[0], e[1], e[2], e[3],
            e[4], e[5], e[6], e[7],
            f[0], f[1], f[2], f[3],
            f[4], f[5], f[6], f[7],
            g[0], g[1], g[2], g[3],
            g[4], g[5], g[6], g[7],
            h[0], h[1], h[2], h[3],
            h[4], h[5], h[6], h[7],
        ])
    }

    /// Resets the hash state to the in-progress state.
    #[must_use]
    pub fn reset(&self) -> Update {
        Update::new()
    }
}

impl core::Finalize for Finalize {
    type Digest = Digest;
    type Update = Update;

    fn digest(&self) -> Self::Digest {
        self.digest()
    }

    fn reset(&self) -> Self::Update {
        self.reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let digest = default().digest().to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = new().digest().to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    #[test]
    fn reset() {
        let digest = new().update("data").reset().digest().to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = new().update("data").finalize().reset().digest().to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    #[test]
    fn hello_world() {
        let digest = new().update("Hello World").digest().to_hex_lowercase();
        assert_eq!(digest, "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b");

        let digest = new()
            .update("Hello")
            .update(" ")
            .update("World")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b");
    }

    #[test]
    fn rust_book() {
        let phrase = "Welcome to The Rust Programming Language, an introductory book about Rust. The Rust programming \
                      language helps you write faster, more reliable software. High-level ergonomics and low-level \
                      control are often at odds in programming language design; Rust challenges that conflict. \
                      Through balancing powerful technical capacity and a great developer experience, Rust gives you \
                      the option to control low-level details (such as memory usage) without all the hassle \
                      traditionally associated with such control.";

        let digest = hash(phrase).to_hex_lowercase();
        assert_eq!(digest, "72a43851dd05d04f09faf88602c3a921867dd0410bd8ed2db223adc7586d93951e9d0367db023076bd0573064facebf127a0674d56d7ee4e3f0c3e334e277278");
    }

    #[test]
    fn zeroes() {
        let data = vec![0u8; 128];

        let digest = new().update(&data[..120]).digest().to_hex_lowercase();
        assert_eq!(digest, "c106c47ad6eb79cd2290681cb04cb183effbd0b49402151385b2d07be966e2d50bc9db78e00bf30bb567ccdd3a1c7847260c94173ba215a0feabb0edeb643ff0");

        let digest = new()
            .update(&data[..120])
            .update(&data[120..])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "ab942f526272e456ed68a979f50202905ca903a141ed98443567b11ef0bf25a552d639051a01be58558122c58e3de07d749ee59ded36acf0c55cd91924d6ba11");
    }
}
