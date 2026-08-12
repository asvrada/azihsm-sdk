// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_mbor_types::MaskedKeyError;
use azihsm_ddi_mbor_types::AES_CBC_256_KEY_SIZE;
use azihsm_ddi_mbor_types::HMAC384_KEY_SIZE;

/// Splits a combined AES-HMAC key into separate AES and HMAC components.
///
/// # Arguments
/// * `key` - The combined key containing both AES and HMAC key material
///
/// # Returns
/// * `Ok((aes_key, hmac_key))` - Tuple containing the AES key and HMAC key slices
/// * `Err(MaskedKeyError::AesHmacComboKeyInvalid)` - If the key length is incorrect
pub fn split_aes_hmac_key(key: &[u8]) -> Result<(&[u8], &[u8]), MaskedKeyError> {
    if key.len() != (AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE) {
        Err(MaskedKeyError::AesHmacComboKeyInvalid)?;
    }
    let aes_key = &key[..AES_CBC_256_KEY_SIZE];
    let hmac_key = &key[AES_CBC_256_KEY_SIZE..];
    Ok((aes_key, hmac_key))
}
