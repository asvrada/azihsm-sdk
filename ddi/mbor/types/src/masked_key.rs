// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::ops::Range;

extern crate alloc;

use azihsm_ddi_mbor_derive::Ddi;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;

use crate::*;

pub const HMAC384_TAG_SIZE: usize = 48;
pub const HMAC384_KEY_SIZE: usize = 48;

pub const AES_BLOCK_SIZE: usize = 16;
pub const AES_CBC_IV_SIZE: usize = 16;
pub const AES_CBC_TAG_SIZE: usize = HMAC384_TAG_SIZE;
pub const AES_CBC_256_KEY_SIZE: usize = 32;

pub const AES_GCM_IV_SIZE: usize = 12;
pub const AES_GCM_TAG_SIZE: usize = 16;

/// An encoded masked-key blob: the wire-format byte representation produced
/// by encoding a masked key (header + AES payload + tag) and consumed when
/// decoding one back via `MaskedKey::decode`. This is a plain alias over
/// `Vec<u8>` used to make ownership of masked-key buffers self-documenting
/// at API boundaries; it is not a distinct type and imposes no additional
/// invariants beyond being a well-formed masked key once fully encoded.
pub type MaskedKeyBlob = alloc::vec::Vec<u8>;

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[repr(C, packed)]
#[derive(Debug, IntoBytes, KnownLayout, PartialEq, Eq, Clone, Copy, TryFromBytes, Immutable)]
pub struct MaskedKeyHeader {
    /// Version of the masked key format.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub version: u16,

    /// Masking Algorithm.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub algorithm: MaskingKeyAlgorithm,
}

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[repr(C, packed)]
#[derive(Debug, IntoBytes, KnownLayout, PartialEq, Eq, Clone, Copy, TryFromBytes, Immutable)]
pub struct MaskedKeyAesHeader {
    /// Length of the IV (Initialization Vector) in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub iv_len: u16,

    /// Length of post IV padding in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub post_iv_pad_len: u16,

    /// Length of the metadata in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub metadata_len: u16,

    /// Length of the post metadata padding in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub post_metadata_pad_len: u16,

    /// Length of the encrypted key in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub encrypted_key_len: u16,

    /// Length of the post encrypted key padding in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub post_encrypted_key_pad_len: u16,

    /// Length of the integrity tag in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub tag_len: u16,

    /// Reserved.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub reserved: [u8; 34],
    //
    // Following fields are variable length fields
    // IV (Initialization Vector).
    //     Integrity protected: Yes, by the integrity tag.
    //     Encrypted: No.
    // iv: [u8; iv_len],

    // Post IV Padding.
    //     Integrity protected: Yes, by the integrity tag.
    //     Encrypted: No.
    // post_iv_pad: [u8; post_iv_pad_len],

    // Masked key metadata in MBOR format.
    //     Integrity protected: Yes, by the integrity tag.
    //     Encrypted: No.
    // metadata: [u8; metadata_len],

    // Post Metadata Padding.
    //     Integrity protected: Yes, by the integrity tag.
    //     Encrypted: No.
    // post_metadata_pad: [u8; post_metadata_pad_len],

    // Encrypted key in device native format.
    //     Integrity protected: Yes, by the integrity tag.
    //     Encrypted: Yes.
    // encrypted_key: [u8; encrypted_key_len],

    // Post Encrypted Key Padding.
    //     Integrity protected: Yes (for AES CBS), by the integrity tag.
    //     Encrypted: No.
    // post_encrypted_key_pad: [u8; post_encrypted_key_pad_len],

    // Integrity tag.
    //     Integrity protected: Not applicable.
    //     Encrypted: No.
    // tag: [u8; tag_len],
}

const _: () = {
    assert!(
        core::mem::size_of::<MaskedKeyHeader>().is_multiple_of(4),
        "MaskedKeyHeader size must be a multiple of 4 bytes"
    );

    assert!(
        core::mem::size_of::<MaskedKeyAesHeader>().is_multiple_of(4),
        "MaskedKeyAesHeader size must be a multiple of 4 bytes"
    );
};

/// Layout of the variable-length fields that follow `MaskedKeyHeader` +
/// `MaskedKeyAesHeader` for AES-based masked keys (CBC, GCM).
///
/// This is the single source of truth for computing the byte offsets/ranges
/// of each field within the payload; every accessor on `MaskedKeyAes` and
/// `PreEncodedMaskedKeyAes` derives its slices from these ranges instead of
/// re-deriving the arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskedKeyAesLayout {
    pub iv_len: usize,
    pub post_iv_pad_len: usize,
    pub metadata_len: usize,
    pub post_metadata_pad_len: usize,
    pub encrypted_key_len: usize,
    pub post_encrypted_key_pad_len: usize,
    pub tag_len: usize,
}

impl MaskedKeyAesLayout {
    /// Calculates the layout for a masked key given the algorithm and content
    /// lengths, aligning each variable-length field to a 4-byte boundary.
    pub fn calculate(
        algo: MaskingKeyAlgorithm,
        metadata_len: usize,
        encrypted_key_len: usize,
    ) -> Self {
        let (iv_len, tag_len) = match algo {
            MaskingKeyAlgorithm::AesCbc256Hmac384 => (AES_CBC_IV_SIZE, AES_CBC_TAG_SIZE),
            MaskingKeyAlgorithm::AesGcm256 => (AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE),
            _ => unreachable!(), // Invalid algorithm, should not happen
        };

        Self {
            iv_len,
            post_iv_pad_len: iv_len.next_multiple_of(4) - iv_len,
            metadata_len,
            post_metadata_pad_len: metadata_len.next_multiple_of(4) - metadata_len,
            encrypted_key_len,
            post_encrypted_key_pad_len: encrypted_key_len.next_multiple_of(4) - encrypted_key_len,
            tag_len,
        }
    }

    /// Returns the total length of the encoded masked key, including both
    /// `MaskedKeyHeader` and `MaskedKeyAesHeader`.
    pub fn total_len(&self) -> usize {
        size_of::<MaskedKeyHeader>() + size_of::<MaskedKeyAesHeader>() + self.payload_len()
    }

    /// Returns the length of the variable-length payload that follows both
    /// headers (IV, metadata, encrypted key, tag, and their padding).
    pub fn payload_len(&self) -> usize {
        self.iv_len
            + self.post_iv_pad_len
            + self.metadata_len
            + self.post_metadata_pad_len
            + self.encrypted_key_len
            + self.post_encrypted_key_pad_len
            + self.tag_len
    }

    /// Byte range of the IV within the payload, relative to the start of the
    /// payload (i.e. right after `MaskedKeyAesHeader`).
    pub fn iv_range(&self) -> Range<usize> {
        0..self.iv_len
    }

    /// Byte range of the post-IV padding within the payload.
    pub fn post_iv_pad_range(&self) -> Range<usize> {
        let start = self.iv_range().end;
        start..start + self.post_iv_pad_len
    }

    /// Byte range of the metadata within the payload.
    pub fn metadata_range(&self) -> Range<usize> {
        let start = self.post_iv_pad_range().end;
        start..start + self.metadata_len
    }

    /// Byte range of the post-metadata padding within the payload.
    pub fn post_metadata_pad_range(&self) -> Range<usize> {
        let start = self.metadata_range().end;
        start..start + self.post_metadata_pad_len
    }

    /// Byte range of the encrypted key within the payload.
    pub fn encrypted_key_range(&self) -> Range<usize> {
        let start = self.post_metadata_pad_range().end;
        start..start + self.encrypted_key_len
    }

    /// Byte range of the post-encrypted-key padding within the payload.
    pub fn post_encrypted_key_pad_range(&self) -> Range<usize> {
        let start = self.encrypted_key_range().end;
        start..start + self.post_encrypted_key_pad_len
    }

    /// Byte range of the integrity tag within the payload.
    pub fn tag_range(&self) -> Range<usize> {
        let start = self.post_encrypted_key_pad_range().end;
        start..start + self.tag_len
    }

    /// Validates that the lengths are self-consistent: non-zero where
    /// required, a recognized IV size, and each field 4-byte aligned once its
    /// padding is included.
    pub fn validate(&self) -> Result<(), MaskedKeyError> {
        if self.encrypted_key_len == 0 || self.metadata_len == 0 || self.tag_len == 0 {
            return Err(MaskedKeyError::InvalidLength);
        }

        if self.iv_len != AES_CBC_IV_SIZE && self.iv_len != AES_GCM_IV_SIZE {
            return Err(MaskedKeyError::InvalidLength);
        }

        if !(self.iv_len + self.post_iv_pad_len).is_multiple_of(4)
            || !(self.metadata_len + self.post_metadata_pad_len).is_multiple_of(4)
            || !(self.encrypted_key_len + self.post_encrypted_key_pad_len).is_multiple_of(4)
        {
            return Err(MaskedKeyError::InvalidLength);
        }

        Ok(())
    }
}

impl From<&MaskedKeyAesHeader> for MaskedKeyAesLayout {
    fn from(header: &MaskedKeyAesHeader) -> Self {
        Self {
            iv_len: header.iv_len as usize,
            post_iv_pad_len: header.post_iv_pad_len as usize,
            metadata_len: header.metadata_len as usize,
            post_metadata_pad_len: header.post_metadata_pad_len as usize,
            encrypted_key_len: header.encrypted_key_len as usize,
            post_encrypted_key_pad_len: header.post_encrypted_key_pad_len as usize,
            tag_len: header.tag_len as usize,
        }
    }
}

/// AES-specific masked key: a read-only, runtime view over decoded masked
/// key bytes.
#[derive(Debug)]
pub struct MaskedKeyAes<'a> {
    header: MaskedKeyHeader,
    layout: MaskedKeyAesLayout,
    /// The variable-length payload, i.e. the bytes immediately following
    /// `MaskedKeyAesHeader`.
    payload: &'a [u8],
}

impl<'a> MaskedKeyAes<'a> {
    /// Creates a new `MaskedKeyAes` view.
    ///
    /// `payload` must start at the beginning of `MaskedKeyAesHeader` (i.e.
    /// immediately after `MaskedKeyHeader`) and be at least
    /// `size_of::<MaskedKeyAesHeader>() + layout.payload_len()` bytes long.
    pub fn new(header: MaskedKeyHeader, layout: MaskedKeyAesLayout, payload: &'a [u8]) -> Self {
        Self {
            header,
            layout,
            payload: &payload[size_of::<MaskedKeyAesHeader>()..],
        }
    }

    /// Returns the header.
    pub fn header(&self) -> &MaskedKeyHeader {
        &self.header
    }

    /// Returns the layout information.
    pub fn layout(&self) -> &MaskedKeyAesLayout {
        &self.layout
    }

    /// Returns the IV (Initialization Vector) slice.
    pub fn iv(&self) -> &[u8] {
        &self.payload[self.layout.iv_range()]
    }

    /// Returns the encrypted key data slice.
    pub fn encrypted_key(&self) -> &[u8] {
        &self.payload[self.layout.encrypted_key_range()]
    }

    /// Returns the metadata slice.
    pub fn metadata(&self) -> &[u8] {
        &self.payload[self.layout.metadata_range()]
    }

    /// Returns the authentication tag slice.
    pub fn tag(&self) -> &[u8] {
        &self.payload[self.layout.tag_range()]
    }
}

/// A masked key buffer prepared for encoding: `MaskedKeyHeader` and
/// `MaskedKeyAesHeader` have already been written, and the variable-length
/// fields (IV, metadata, encrypted key, tag) can be filled in through the
/// accessors below.
#[derive(Debug)]
pub struct PreEncodedMaskedKeyAes<'a> {
    algo: MaskingKeyAlgorithm,
    buffer: &'a mut [u8],
    layout: MaskedKeyAesLayout,
}

/// Enum to handle different pre-encoded masked key types.
#[derive(Debug)]
pub enum PreEncodedMaskedKeyType<'a> {
    Aes(PreEncodedMaskedKeyAes<'a>),
}

impl<'a> PreEncodedMaskedKeyAes<'a> {
    /// Offset of the variable-length payload within `buffer`, i.e. the
    /// offset right after `MaskedKeyHeader` + `MaskedKeyAesHeader`.
    fn payload_offset() -> usize {
        size_of::<MaskedKeyHeader>() + size_of::<MaskedKeyAesHeader>()
    }

    fn payload(&self) -> &[u8] {
        &self.buffer[Self::payload_offset()..]
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        let offset = Self::payload_offset();
        &mut self.buffer[offset..]
    }

    /// Returns the masking key algorithm used for this masked key.
    pub fn algo(&self) -> MaskingKeyAlgorithm {
        self.algo
    }

    /// Returns the layout information.
    pub fn layout(&self) -> &MaskedKeyAesLayout {
        &self.layout
    }

    /// Returns an immutable slice of the Initialization Vector (IV).
    pub fn iv(&self) -> &[u8] {
        &self.payload()[self.layout.iv_range()]
    }

    /// Returns a mutable slice of the Initialization Vector (IV).
    pub fn iv_mut(&mut self) -> &mut [u8] {
        let range = self.layout.iv_range();
        &mut self.payload_mut()[range]
    }

    /// Returns an immutable slice of the encrypted key data.
    pub fn encrypted_key(&self) -> &[u8] {
        &self.payload()[self.layout.encrypted_key_range()]
    }

    /// Returns a mutable slice of the encrypted key data.
    pub fn encrypted_key_mut(&mut self) -> &mut [u8] {
        let range = self.layout.encrypted_key_range();
        &mut self.payload_mut()[range]
    }

    /// Returns an immutable slice of the metadata.
    pub fn metadata(&self) -> &[u8] {
        &self.payload()[self.layout.metadata_range()]
    }

    /// Returns a mutable slice of the metadata.
    pub fn metadata_mut(&mut self) -> &mut [u8] {
        let range = self.layout.metadata_range();
        &mut self.payload_mut()[range]
    }

    /// Returns an immutable slice of the integrity tag.
    pub fn tag(&self) -> &[u8] {
        &self.payload()[self.layout.tag_range()]
    }

    /// Returns a mutable slice of the integrity tag.
    pub fn tag_mut(&mut self) -> &mut [u8] {
        let range = self.layout.tag_range();
        &mut self.payload_mut()[range]
    }

    /// Returns the data to be tagged based on the algorithm type.
    /// For AES CBC: everything except the tag itself.
    /// For AES GCM: data up to (but not including) the encrypted_key.
    pub fn tagged_data(&self) -> &[u8] {
        match self.algo {
            MaskingKeyAlgorithm::AesCbc256Hmac384 => {
                // For AES CBC, tag everything except the tag itself.
                let end = self.buffer.len() - self.layout.tag_len;
                &self.buffer[..end]
            }
            MaskingKeyAlgorithm::AesGcm256 => {
                // For AES GCM, tag only up to (but not including) the encrypted_key.
                let end = Self::payload_offset() + self.layout.post_metadata_pad_range().end;
                &self.buffer[..end]
            }
            _ => unreachable!(),
        }
    }
}

impl PreEncodedMaskedKeyType<'_> {
    /// Returns an immutable slice of the encrypted key data.
    pub fn encrypted_key(&self) -> &[u8] {
        match self {
            PreEncodedMaskedKeyType::Aes(aes) => aes.encrypted_key(),
        }
    }

    /// Returns a mutable slice of the encrypted key data.
    pub fn encrypted_key_mut(&mut self) -> &mut [u8] {
        match self {
            PreEncodedMaskedKeyType::Aes(aes) => aes.encrypted_key_mut(),
        }
    }

    /// Returns an immutable slice of the metadata.
    pub fn metadata(&self) -> &[u8] {
        match self {
            PreEncodedMaskedKeyType::Aes(aes) => aes.metadata(),
        }
    }

    /// Returns a mutable slice of the metadata.
    pub fn metadata_mut(&mut self) -> &mut [u8] {
        match self {
            PreEncodedMaskedKeyType::Aes(aes) => aes.metadata_mut(),
        }
    }

    /// Returns the masking key algorithm used for this masked key.
    pub fn algo(&self) -> MaskingKeyAlgorithm {
        match self {
            PreEncodedMaskedKeyType::Aes(aes) => aes.algo(),
        }
    }

    /// Returns the data to be tagged based on the algorithm type.
    pub fn tagged_data(&self) -> &[u8] {
        match self {
            PreEncodedMaskedKeyType::Aes(aes) => aes.tagged_data(),
        }
    }
}

/// Namespace for the masked-key encode/decode entry points. This type holds
/// no state; it exists purely to group the associated functions below
/// (`encoded_length`, `pre_encode`) and to serve as the target for the
/// `MaskedKeyEncode`/`MaskedKeyDecode` trait implementations in the
/// simulator crate.
#[derive(Debug, Clone, Copy)]
pub struct MaskedKey;

impl MaskedKey {
    /// Returns the buffer size needed to encode a masked key.
    ///
    /// # Arguments
    /// * `algo` - The masking key algorithm used.
    /// * `metadata_len` - The length of the metadata.
    /// * `encrypted_key_len` - The length of the encrypted key.
    ///
    /// # Returns
    /// * `usize` - The total length of the masked key structure after encoding
    pub fn encoded_length(
        algo: MaskingKeyAlgorithm,
        metadata_len: usize,
        encrypted_key_len: usize,
    ) -> usize {
        MaskedKeyAesLayout::calculate(algo, metadata_len, encrypted_key_len).total_len()
    }

    /// Pre-encodes a masked key.
    /// This function prepares the masked key for encoding by calculating the layout and filling the header.
    ///
    /// # Arguments
    /// * `version` - The version of the masked key format.
    /// * `algo` - The masking key algorithm used.
    /// * `metadata_len` - The length of the metadata.
    /// * `encrypted_key_len` - The length of the key after encryption.
    /// * `out_data` - The output buffer to hold the pre-encoded masked key.
    ///
    /// # Returns
    /// * `Result<PreEncodedMaskedKeyType<'a>, MaskedKeyError>` - The pre-encoded masked key structure.
    pub fn pre_encode(
        version: u16,
        algo: MaskingKeyAlgorithm,
        metadata_len: usize,
        encrypted_key_len: usize,
        out_data: &mut [u8],
    ) -> Result<PreEncodedMaskedKeyType<'_>, MaskedKeyError> {
        if encrypted_key_len == 0 {
            Err(MaskedKeyError::InvalidLength)?;
        }

        // Calculate the layout of the masked key.
        let layout = MaskedKeyAesLayout::calculate(algo, metadata_len, encrypted_key_len);

        // Check if the output buffer is exactly the right size.
        if out_data.len() != layout.total_len() {
            Err(MaskedKeyError::InvalidLength)?;
        }

        let (header_slice, remaining) = out_data.split_at_mut(size_of::<MaskedKeyHeader>());
        let header: &mut MaskedKeyHeader = MaskedKeyHeader::try_mut_from_bytes(header_slice)
            .map_err(|_| MaskedKeyError::InvalidLength)?;

        header.version = version;
        header.algorithm = algo;

        // Set up the payload based on the algorithm
        match algo {
            MaskingKeyAlgorithm::AesCbc256Hmac384 | MaskingKeyAlgorithm::AesGcm256 => {
                // For AES algorithms, we need to set up the AES payload
                let (aes_payload, _) = remaining.split_at_mut(size_of::<MaskedKeyAesHeader>());
                let payload: &mut MaskedKeyAesHeader =
                    MaskedKeyAesHeader::try_mut_from_bytes(aes_payload)
                        .map_err(|_| MaskedKeyError::InvalidLength)?;

                payload.iv_len = layout.iv_len as u16;
                payload.post_iv_pad_len = layout.post_iv_pad_len as u16;
                payload.metadata_len = layout.metadata_len as u16;
                payload.post_metadata_pad_len = layout.post_metadata_pad_len as u16;
                payload.encrypted_key_len = layout.encrypted_key_len as u16;
                payload.post_encrypted_key_pad_len = layout.post_encrypted_key_pad_len as u16;
                payload.tag_len = layout.tag_len as u16;
            }
            _ => {
                Err(MaskedKeyError::InvalidAlgorithm)?;
            }
        }

        Ok(PreEncodedMaskedKeyType::Aes(PreEncodedMaskedKeyAes {
            algo,
            buffer: out_data,
            layout,
        }))
    }
}

#[derive(Debug)]
pub enum MaskedKeyError {
    /// Invalid algorithm
    InvalidAlgorithm,
    /// Invalid length
    InvalidLength,
    /// The destination buffer is too small to hold the encoded data.
    InsufficientBuffer,
    /// Decoding error
    DecodeError,
    /// The header is malformed or contains invalid data.
    HeaderDecodeError,
    /// The header could not be encoded.
    HeaderEncodeError,
    /// The masking key algorithm specified is not supported.
    InvalidMaskingKeyAlgorithm,
    /// The HMAC tag generation failed.
    HmacTagGenerationFailed,
    /// The HMAC tag verification failed.
    HmacTagVerificationFailed,
    /// Invalid AES key.
    AesKeyInvalid,
    /// AES encryption failed.
    AesEncryptionFailed,
    /// AES decryption failed.
    AesDecryptionFailed,
    /// The AES key is not set in the environment.
    AesKeyNotSet,
    /// The HMAC key is not set in the environment.
    HmacKeyNotSet,
    /// The HMAC key is invalid.
    HmacKeyInvalid,
    /// The metadata encoding failed.
    MetadataEncodeError,
    /// The metadata decoding failed.
    MetadataDecodeError,
    /// The combined AES and HMAC key is invalid.
    AesHmacComboKeyInvalid,
    /// The key derivation function (KBKDF) failed.
    KbkdfFailed,
    /// Invalid Encrypted Key Length
    InvalidEncryptedKeyLength,
}

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(u16)]
pub enum MaskingKeyAlgorithm {
    /// AES CBC 256 with HMAC 384
    AesCbc256Hmac384 = 1,

    /// AES GCM 256
    AesGcm256 = 2,
}

impl TryFrom<u16> for MaskingKeyAlgorithm {
    type Error = MaskedKeyError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AesCbc256Hmac384),
            2 => Ok(Self::AesGcm256),
            _ => Err(MaskedKeyError::InvalidAlgorithm),
        }
    }
}

impl From<MaskingKeyAlgorithm> for u16 {
    fn from(algo: MaskingKeyAlgorithm) -> u16 {
        match algo {
            MaskingKeyAlgorithm::AesCbc256Hmac384 => 1,
            MaskingKeyAlgorithm::AesGcm256 => 2,
            _ => unreachable!(),
        }
    }
}

/// Masked Key Metadata
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiMaskedKeyMetadata {
    /// SVN
    #[ddi(id = 1)]
    pub svn: Option<u64>,

    /// Key Kind
    #[ddi(id = 2)]
    pub key_type: DdiKeyType,

    /// Key Attributes
    #[ddi(id = 3)]
    pub key_attributes: DdiMaskedKeyAttributes,

    /// Key BKS2 Number
    #[ddi(id = 4)]
    /// The BKS2 index ndicating which BKS2 this key belongs to.
    pub bks2_index: Option<u16>,

    /// Key Name
    #[ddi(id = 5)]
    pub key_tag: Option<u16>,

    /// Key label
    #[ddi(id = 6)]
    pub key_label: MborByteArray<DDI_MAX_KEY_LABEL_LENGTH>,

    /// Key Length (which will be stored in the vault) in bytes
    #[ddi(id = 7)]
    pub key_length: u16,
}

/// DDI Key Properties Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Clone, PartialEq, Eq)]
#[ddi(map)]
pub struct DdiMaskedKeyAttributes {
    /// Key Attributes Blob
    #[ddi(id = 1)]
    pub blob: [u8; 32],
}
