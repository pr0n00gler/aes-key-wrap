//! Pure-Rust AES Key Wrap as specified by [RFC 3394] and [RFC 5649].
//!
//! [`KeyWrapMode::Rfc3394`] implements unpadded AES-KW with the default
//! `A6A6A6A6A6A6A6A6` initial value. [`KeyWrapMode::Rfc5649`] implements
//! AES-KWP, including its alternative initial value and zero padding. Both
//! modes accept 128-, 192-, and 256-bit AES key-encryption keys (KEKs).
//!
//! The caller supplies the output buffer, so wrapping and unwrapping do not
//! allocate. When ciphertext fails the RFC integrity check, [`unwrap_key`]
//! zeroizes the entire plaintext output buffer before returning an error.
//!
//! # Security considerations
//!
//! AES-KW and AES-KWP are deterministic: wrapping the same plaintext with the
//! same KEK and mode produces the same ciphertext. They provide neither a
//! nonce nor associated data, so applications must provide any required
//! context binding, freshness, or replay protection separately. Use an
//! authenticated-encryption scheme instead when nonce-based encryption or
//! associated data is required.
//!
//! The integrity register provides approximately a 64-bit integrity check.
//! Callers handling attacker-controlled ciphertext should rate-limit or
//! otherwise bound failed unwrap attempts. KEKs should have security strength
//! at least equal to the wrapped material and should be separated across
//! protocols and purposes.
//!
//! RFC 3394 inputs are restricted to the `n < 2^54` semiblock limit specified
//! for AES-KW by [NIST SP 800-38F]. RFC 5649 plaintext is restricted to
//! `1..=2^32-1` bytes as clarified by [verified erratum 6943]. This crate does
//! not implement application-defined alternative initial values.
//!
//! [RFC 3394]: https://www.rfc-editor.org/rfc/rfc3394
//! [RFC 5649]: https://www.rfc-editor.org/rfc/rfc5649
//! [NIST SP 800-38F]: https://doi.org/10.6028/NIST.SP.800-38F
//! [verified erratum 6943]: https://www.rfc-editor.org/errata/eid6943

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::{error, fmt};

use aes::{
    Aes128, Aes192, Aes256,
    cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit, typenum::U16},
};
use subtle::{ConstantTimeEq, ConstantTimeGreater};
use zeroize::{Zeroize, Zeroizing};

const BLOCK_LEN: usize = 8;
const AES_BLOCK_LEN: usize = 16;
const RFC_3394_MIN_PLAINTEXT_LEN: usize = 2 * BLOCK_LEN;
const RFC_3394_MIN_CIPHERTEXT_LEN: usize = RFC_3394_MIN_PLAINTEXT_LEN + BLOCK_LEN;
const RFC_5649_MIN_CIPHERTEXT_LEN: usize = AES_BLOCK_LEN;
const DEFAULT_IV: [u8; BLOCK_LEN] = [0xA6; BLOCK_LEN];
const RFC_5649_IV_PREFIX: [u8; BLOCK_LEN / 2] = [0xA6, 0x59, 0x59, 0xA6];
const ROUNDS: usize = 6;
const RFC_3394_MAX_BLOCK_COUNT_EXCLUSIVE: u64 = 1 << 54;
const RFC_5649_MAX_PLAINTEXT_LEN: u64 = u32::MAX as u64;
const RFC_5649_MAX_BLOCK_COUNT: u64 = 1 << 29;

/// Selects the AES Key Wrap algorithm used by [`wrap_key`] and [`unwrap_key`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyWrapMode {
    /// Unpadded AES Key Wrap with the default IV from RFC 3394.
    Rfc3394,

    /// AES Key Wrap with Padding and the alternative IV from RFC 5649.
    Rfc5649,
}

impl fmt::Display for KeyWrapMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rfc3394 => formatter.write_str("RFC 3394"),
            Self::Rfc5649 => formatter.write_str("RFC 5649"),
        }
    }
}

/// An input validation or integrity error from AES Key Wrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The KEK was not a valid AES key length.
    InvalidKekLength {
        /// Supplied KEK length in bytes.
        actual: usize,
    },

    /// Plaintext did not meet the selected mode's length requirements.
    InvalidPlaintextLength {
        /// Selected key-wrap mode.
        mode: KeyWrapMode,
        /// Supplied plaintext length in bytes.
        actual: usize,
    },

    /// Ciphertext did not meet the selected mode's length requirements.
    InvalidCiphertextLength {
        /// Selected key-wrap mode.
        mode: KeyWrapMode,
        /// Supplied ciphertext length in bytes.
        actual: usize,
    },

    /// The caller-provided output buffer had the wrong length.
    InvalidOutputLength {
        /// Required output length in bytes.
        expected: usize,
        /// Supplied output length in bytes.
        actual: usize,
    },

    /// The input or required output exceeded the selected mode's length limit.
    InputTooLong,

    /// The selected mode's integrity checks failed.
    IntegrityCheckFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKekLength { actual } => write!(
                formatter,
                "invalid AES KEK length {actual}; expected 16, 24, or 32 bytes"
            ),
            Self::InvalidPlaintextLength {
                mode: KeyWrapMode::Rfc3394,
                actual,
            } => write!(
                formatter,
                "invalid RFC 3394 plaintext length {actual}; expected a multiple of 8 bytes of at least 16 bytes"
            ),
            Self::InvalidPlaintextLength {
                mode: KeyWrapMode::Rfc5649,
                actual,
            } => write!(
                formatter,
                "invalid RFC 5649 plaintext length {actual}; expected between 1 and {} bytes",
                RFC_5649_MAX_PLAINTEXT_LEN
            ),
            Self::InvalidCiphertextLength {
                mode: KeyWrapMode::Rfc3394,
                actual,
            } => write!(
                formatter,
                "invalid RFC 3394 ciphertext length {actual}; expected a multiple of 8 bytes of at least 24 bytes"
            ),
            Self::InvalidCiphertextLength {
                mode: KeyWrapMode::Rfc5649,
                actual,
            } => write!(
                formatter,
                "invalid RFC 5649 ciphertext length {actual}; expected a multiple of 8 bytes of at least 16 bytes"
            ),
            Self::InvalidOutputLength { expected, actual } => write!(
                formatter,
                "invalid output length {actual}; expected exactly {expected} bytes"
            ),
            Self::InputTooLong => {
                formatter.write_str("input exceeds the selected AES Key Wrap mode's length limit")
            }
            Self::IntegrityCheckFailed => {
                formatter.write_str("AES Key Wrap integrity check failed")
            }
        }
    }
}

impl error::Error for Error {}

/// Wraps key data with an AES key-encryption key.
///
/// `kek` must be 16, 24, or 32 bytes. In [`KeyWrapMode::Rfc3394`],
/// `plaintext` must be a multiple of 8 bytes and at least 16 bytes long, and
/// `output` must be exactly 8 bytes longer than `plaintext`. In
/// [`KeyWrapMode::Rfc5649`], `plaintext` must contain between 1 and
/// `2^32-1` bytes, and `output` must have length
/// `8 * (ceil(plaintext.len() / 8) + 1)`.
///
/// Validation errors leave `output` unchanged.
pub fn wrap_key(
    mode: KeyWrapMode,
    kek: &[u8],
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    validate_kek(kek)?;
    let (block_count, expected_output_len) = validate_plaintext(mode, plaintext.len())?;
    validate_output(output, expected_output_len)?;
    validate_block_count(mode, block_count)?;

    match kek.len() {
        16 => wrap_with(
            &Aes128::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
            mode,
            plaintext,
            output,
            block_count,
        ),
        24 => wrap_with(
            &Aes192::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
            mode,
            plaintext,
            output,
            block_count,
        ),
        32 => wrap_with(
            &Aes256::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
            mode,
            plaintext,
            output,
            block_count,
        ),
        _ => unreachable!("KEK length was validated before cipher construction"),
    }

    Ok(())
}

/// Unwraps ciphertext with an AES key-encryption key.
///
/// `kek` must be 16, 24, or 32 bytes. RFC 3394 ciphertext must be a multiple
/// of 8 bytes and at least 24 bytes long. RFC 5649 ciphertext must be a
/// multiple of 8 bytes and at least 16 bytes long. `output` must be exactly 8
/// bytes shorter than `ciphertext`.
///
/// If the RFC integrity check fails, this function zeroizes all of `output`
/// and returns [`Error::IntegrityCheckFailed`] without releasing key data.
/// Input validation errors leave `output` unchanged.
///
/// On success, the returned length identifies the authenticated plaintext in
/// `output`. It equals `output.len()` for RFC 3394. For RFC 5649, the returned
/// length is the authenticated message length indicator, and any remaining
/// bytes in `output` are verified zero padding.
pub fn unwrap_key(
    mode: KeyWrapMode,
    kek: &[u8],
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    validate_kek(kek)?;
    let block_count = validate_ciphertext(mode, ciphertext.len())?;
    validate_output(output, ciphertext.len() - BLOCK_LEN)?;
    let steps = validate_block_count(mode, block_count)?;

    match kek.len() {
        16 => unwrap_with(
            &Aes128::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
            mode,
            ciphertext,
            output,
            block_count,
            steps,
        ),
        24 => unwrap_with(
            &Aes192::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
            mode,
            ciphertext,
            output,
            block_count,
            steps,
        ),
        32 => unwrap_with(
            &Aes256::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
            mode,
            ciphertext,
            output,
            block_count,
            steps,
        ),
        _ => unreachable!("KEK length was validated before cipher construction"),
    }
}

fn validate_kek(kek: &[u8]) -> Result<(), Error> {
    match kek.len() {
        16 | 24 | 32 => Ok(()),
        _ => Err(invalid_kek(kek)),
    }
}

fn invalid_kek(kek: &[u8]) -> Error {
    Error::InvalidKekLength { actual: kek.len() }
}

fn validate_plaintext(mode: KeyWrapMode, plaintext_len: usize) -> Result<(usize, usize), Error> {
    match mode {
        KeyWrapMode::Rfc3394 => {
            if plaintext_len < RFC_3394_MIN_PLAINTEXT_LEN
                || !plaintext_len.is_multiple_of(BLOCK_LEN)
            {
                return Err(Error::InvalidPlaintextLength {
                    mode,
                    actual: plaintext_len,
                });
            }

            let output_len = plaintext_len
                .checked_add(BLOCK_LEN)
                .ok_or(Error::InputTooLong)?;
            Ok((plaintext_len / BLOCK_LEN, output_len))
        }
        KeyWrapMode::Rfc5649 => {
            if plaintext_len == 0 {
                return Err(Error::InvalidPlaintextLength {
                    mode,
                    actual: plaintext_len,
                });
            }

            let plaintext_len_u64 =
                u64::try_from(plaintext_len).map_err(|_| Error::InputTooLong)?;
            let block_count_u64 = checked_rfc5649_block_count(plaintext_len_u64)?;
            let block_count = usize::try_from(block_count_u64).map_err(|_| Error::InputTooLong)?;
            let output_len = block_count
                .checked_add(1)
                .and_then(|blocks| blocks.checked_mul(BLOCK_LEN))
                .ok_or(Error::InputTooLong)?;
            Ok((block_count, output_len))
        }
    }
}

fn validate_ciphertext(mode: KeyWrapMode, ciphertext_len: usize) -> Result<usize, Error> {
    let minimum_len = match mode {
        KeyWrapMode::Rfc3394 => RFC_3394_MIN_CIPHERTEXT_LEN,
        KeyWrapMode::Rfc5649 => RFC_5649_MIN_CIPHERTEXT_LEN,
    };

    if ciphertext_len < minimum_len || !ciphertext_len.is_multiple_of(BLOCK_LEN) {
        return Err(Error::InvalidCiphertextLength {
            mode,
            actual: ciphertext_len,
        });
    }

    Ok((ciphertext_len - BLOCK_LEN) / BLOCK_LEN)
}

fn validate_output(output: &[u8], expected: usize) -> Result<(), Error> {
    if output.len() != expected {
        return Err(Error::InvalidOutputLength {
            expected,
            actual: output.len(),
        });
    }

    Ok(())
}

fn step_count(block_count: usize) -> Result<u64, Error> {
    let block_count = u64::try_from(block_count).map_err(|_| Error::InputTooLong)?;
    checked_step_count(block_count)
}

fn checked_step_count(block_count: u64) -> Result<u64, Error> {
    if block_count >= RFC_3394_MAX_BLOCK_COUNT_EXCLUSIVE {
        return Err(Error::InputTooLong);
    }

    block_count
        .checked_mul(ROUNDS as u64)
        .ok_or(Error::InputTooLong)
}

fn checked_rfc5649_block_count(plaintext_len: u64) -> Result<u64, Error> {
    if plaintext_len > RFC_5649_MAX_PLAINTEXT_LEN {
        return Err(Error::InputTooLong);
    }

    plaintext_len
        .checked_add(BLOCK_LEN as u64 - 1)
        .map(|length| length / BLOCK_LEN as u64)
        .ok_or(Error::InputTooLong)
}

fn validate_block_count(mode: KeyWrapMode, block_count: usize) -> Result<u64, Error> {
    let block_count_u64 = u64::try_from(block_count).map_err(|_| Error::InputTooLong)?;
    if mode == KeyWrapMode::Rfc5649 && block_count_u64 > RFC_5649_MAX_BLOCK_COUNT {
        return Err(Error::InputTooLong);
    }

    step_count(block_count)
}

fn wrap_with<C>(
    cipher: &C,
    mode: KeyWrapMode,
    plaintext: &[u8],
    output: &mut [u8],
    block_count: usize,
) where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    let initial_value = match mode {
        KeyWrapMode::Rfc3394 => DEFAULT_IV,
        KeyWrapMode::Rfc5649 => rfc5649_aiv(plaintext.len()),
    };

    if mode == KeyWrapMode::Rfc5649 && block_count == 1 {
        let mut block = Zeroizing::new([0u8; AES_BLOCK_LEN]);
        block[..BLOCK_LEN].copy_from_slice(&initial_value);
        block[BLOCK_LEN..BLOCK_LEN + plaintext.len()].copy_from_slice(plaintext);
        let aes_block = <&mut Array<u8, U16>>::try_from(&mut block[..])
            .expect("the internal AES block always contains exactly 16 bytes");
        cipher.encrypt_block(aes_block);
        output.copy_from_slice(block.as_ref());
        return;
    }

    match mode {
        KeyWrapMode::Rfc3394 => output[BLOCK_LEN..].copy_from_slice(plaintext),
        KeyWrapMode::Rfc5649 => {
            output[BLOCK_LEN..].zeroize();
            output[BLOCK_LEN..BLOCK_LEN + plaintext.len()].copy_from_slice(plaintext);
        }
    }

    wrap_blocks(cipher, initial_value, output, block_count);
}

fn wrap_blocks<C>(cipher: &C, initial_value: [u8; BLOCK_LEN], output: &mut [u8], block_count: usize)
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    let mut register = Zeroizing::new(initial_value);
    let mut block = Zeroizing::new([0u8; AES_BLOCK_LEN]);
    let mut step = 1u64;

    for _ in 0..ROUNDS {
        for index in 0..block_count {
            let offset = BLOCK_LEN + index * BLOCK_LEN;
            block[..BLOCK_LEN].copy_from_slice(register.as_ref());
            block[BLOCK_LEN..].copy_from_slice(&output[offset..offset + BLOCK_LEN]);

            let aes_block = <&mut Array<u8, U16>>::try_from(&mut block[..])
                .expect("the internal AES block always contains exactly 16 bytes");
            cipher.encrypt_block(aes_block);

            register.copy_from_slice(&block[..BLOCK_LEN]);
            xor_step(&mut register, step);
            output[offset..offset + BLOCK_LEN].copy_from_slice(&block[BLOCK_LEN..]);
            step += 1;
        }
    }

    output[..BLOCK_LEN].copy_from_slice(register.as_ref());
}

fn unwrap_with<C>(
    cipher: &C,
    mode: KeyWrapMode,
    ciphertext: &[u8],
    output: &mut [u8],
    block_count: usize,
    steps: u64,
) -> Result<usize, Error>
where
    C: BlockCipherDecrypt + BlockSizeUser<BlockSize = U16>,
{
    let mut register = Zeroizing::new([0u8; BLOCK_LEN]);

    if mode == KeyWrapMode::Rfc5649 && block_count == 1 {
        let mut block = Zeroizing::new([0u8; AES_BLOCK_LEN]);
        block.copy_from_slice(ciphertext);
        let aes_block = <&mut Array<u8, U16>>::try_from(&mut block[..])
            .expect("the internal AES block always contains exactly 16 bytes");
        cipher.decrypt_block(aes_block);
        register.copy_from_slice(&block[..BLOCK_LEN]);
        output.copy_from_slice(&block[BLOCK_LEN..]);
    } else {
        unwrap_blocks(
            cipher,
            ciphertext,
            output,
            block_count,
            steps,
            &mut register,
        );
    }

    let authenticated_len = match mode {
        KeyWrapMode::Rfc3394 => {
            if bool::from(register.as_ref().ct_eq(&DEFAULT_IV)) {
                Some(output.len())
            } else {
                None
            }
        }
        KeyWrapMode::Rfc5649 => validate_rfc5649_integrity(&register, output),
    };

    if let Some(authenticated_len) = authenticated_len {
        Ok(authenticated_len)
    } else {
        output.zeroize();
        Err(Error::IntegrityCheckFailed)
    }
}

fn unwrap_blocks<C>(
    cipher: &C,
    ciphertext: &[u8],
    output: &mut [u8],
    block_count: usize,
    mut step: u64,
    register: &mut [u8; BLOCK_LEN],
) where
    C: BlockCipherDecrypt + BlockSizeUser<BlockSize = U16>,
{
    let mut block = Zeroizing::new([0u8; AES_BLOCK_LEN]);

    register.copy_from_slice(&ciphertext[..BLOCK_LEN]);
    output.copy_from_slice(&ciphertext[BLOCK_LEN..]);

    for _ in (0..ROUNDS).rev() {
        for index in (0..block_count).rev() {
            let offset = index * BLOCK_LEN;
            xor_step(register, step);
            block[..BLOCK_LEN].copy_from_slice(register.as_ref());
            block[BLOCK_LEN..].copy_from_slice(&output[offset..offset + BLOCK_LEN]);

            let aes_block = <&mut Array<u8, U16>>::try_from(&mut block[..])
                .expect("the internal AES block always contains exactly 16 bytes");
            cipher.decrypt_block(aes_block);

            register.copy_from_slice(&block[..BLOCK_LEN]);
            output[offset..offset + BLOCK_LEN].copy_from_slice(&block[BLOCK_LEN..]);
            step -= 1;
        }
    }
}

fn rfc5649_aiv(plaintext_len: usize) -> [u8; BLOCK_LEN] {
    let mut aiv = [0u8; BLOCK_LEN];
    aiv[..RFC_5649_IV_PREFIX.len()].copy_from_slice(&RFC_5649_IV_PREFIX);
    let mli = u32::try_from(plaintext_len)
        .expect("RFC 5649 plaintext length was validated before AIV construction");
    aiv[RFC_5649_IV_PREFIX.len()..].copy_from_slice(&mli.to_be_bytes());
    aiv
}

fn validate_rfc5649_integrity(register: &[u8; BLOCK_LEN], output: &[u8]) -> Option<usize> {
    let prefix_valid = register[..RFC_5649_IV_PREFIX.len()].ct_eq(&RFC_5649_IV_PREFIX);
    let mli = u32::from_be_bytes(
        register[RFC_5649_IV_PREFIX.len()..]
            .try_into()
            .expect("the MLI is always four bytes"),
    );
    let mli_u64 = u64::from(mli);
    let padded_len =
        u64::try_from(output.len()).expect("RFC 5649 output length always fits in u64");
    let lower_bound = padded_len - BLOCK_LEN as u64;
    let length_valid = mli_u64.ct_gt(&lower_bound) & !mli_u64.ct_gt(&padded_len);
    let padding_len = padded_len.wrapping_sub(mli_u64);
    let mut padding_valid = 0u8.ct_eq(&0);

    for index_from_end in 0..BLOCK_LEN - 1 {
        let must_be_zero = padding_len.ct_gt(&(index_from_end as u64));
        let byte_is_zero = output[output.len() - 1 - index_from_end].ct_eq(&0);
        padding_valid &= !must_be_zero | byte_is_zero;
    }

    if bool::from(prefix_valid & length_valid & padding_valid) {
        Some(mli as usize)
    } else {
        None
    }
}

fn xor_step(register: &mut [u8; BLOCK_LEN], step: u64) {
    *register = (u64::from_be_bytes(*register) ^ step).to_be_bytes();
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVector {
        kek: &'static str,
        plaintext: &'static str,
        ciphertext: &'static str,
    }

    const RFC_3394_VECTORS: &[TestVector] = &[
        TestVector {
            kek: "000102030405060708090A0B0C0D0E0F",
            plaintext: "00112233445566778899AABBCCDDEEFF",
            ciphertext: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
        },
        TestVector {
            kek: "000102030405060708090A0B0C0D0E0F1011121314151617",
            plaintext: "00112233445566778899AABBCCDDEEFF",
            ciphertext: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
        },
        TestVector {
            kek: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            plaintext: "00112233445566778899AABBCCDDEEFF",
            ciphertext: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
        },
        TestVector {
            kek: "000102030405060708090A0B0C0D0E0F1011121314151617",
            plaintext: "00112233445566778899AABBCCDDEEFF0001020304050607",
            ciphertext: "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
        },
        TestVector {
            kek: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            plaintext: "00112233445566778899AABBCCDDEEFF0001020304050607",
            ciphertext: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
        },
        TestVector {
            kek: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            plaintext: "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            ciphertext: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        },
    ];

    const RFC_5649_VECTORS: &[TestVector] = &[
        TestVector {
            kek: "5840DF6E29B02AF1AB493B705BF16EA1AE8338F4DCC176A8",
            plaintext: "C37B7E6492584340BED12207808941155068F738",
            ciphertext: "138BDEAA9B8FA7FC61F97742E72248EE5AE6AE5360D1AE6A5F54F373FA543B6A",
        },
        TestVector {
            kek: "5840DF6E29B02AF1AB493B705BF16EA1AE8338F4DCC176A8",
            plaintext: "466F7250617369",
            ciphertext: "AFBEB0F07DFBF5419200F2CCB50BB24F",
        },
    ];

    #[test]
    fn matches_all_rfc_3394_test_vectors() {
        for vector in RFC_3394_VECTORS {
            let kek = decode_hex(vector.kek);
            let plaintext = decode_hex(vector.plaintext);
            let expected_ciphertext = decode_hex(vector.ciphertext);
            let mut ciphertext = vec![0xCC; expected_ciphertext.len()];

            wrap_key(KeyWrapMode::Rfc3394, &kek, &plaintext, &mut ciphertext).unwrap();
            assert_eq!(ciphertext, expected_ciphertext);

            let mut unwrapped = vec![0xCC; plaintext.len()];
            assert_eq!(
                unwrap_key(KeyWrapMode::Rfc3394, &kek, &ciphertext, &mut unwrapped,),
                Ok(plaintext.len())
            );
            assert_eq!(unwrapped, plaintext);
        }
    }

    #[test]
    fn matches_all_rfc_5649_test_vectors() {
        for vector in RFC_5649_VECTORS {
            let kek = decode_hex(vector.kek);
            let plaintext = decode_hex(vector.plaintext);
            let expected_ciphertext = decode_hex(vector.ciphertext);
            let mut ciphertext = vec![0xCC; expected_ciphertext.len()];

            wrap_key(KeyWrapMode::Rfc5649, &kek, &plaintext, &mut ciphertext).unwrap();
            assert_eq!(ciphertext, expected_ciphertext);

            let mut unwrapped = vec![0xCC; ciphertext.len() - BLOCK_LEN];
            assert_eq!(
                unwrap_key(KeyWrapMode::Rfc5649, &kek, &ciphertext, &mut unwrapped,),
                Ok(plaintext.len())
            );
            assert_eq!(&unwrapped[..plaintext.len()], plaintext);
            assert!(unwrapped[plaintext.len()..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn round_trips_multiple_key_and_plaintext_lengths() {
        for kek_len in [16, 24, 32] {
            let kek: Vec<u8> = (0..kek_len)
                .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
                .collect();

            for plaintext_len in [16, 24, 32, 40, 128, 1024] {
                let plaintext: Vec<u8> = (0..plaintext_len)
                    .map(|index| (index as u8).wrapping_mul(29).wrapping_add(11))
                    .collect();
                let mut ciphertext = vec![0; plaintext_len + BLOCK_LEN];
                let mut unwrapped = vec![0; plaintext_len];

                wrap_key(KeyWrapMode::Rfc3394, &kek, &plaintext, &mut ciphertext).unwrap();
                assert_eq!(
                    unwrap_key(KeyWrapMode::Rfc3394, &kek, &ciphertext, &mut unwrapped,),
                    Ok(plaintext.len())
                );

                assert_eq!(unwrapped, plaintext);
            }
        }
    }

    #[test]
    fn rfc_5649_round_trips_padding_boundaries_with_every_aes_key_size() {
        let plaintext_lengths = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 24, 31, 32, 33, 128,
            384, 1024,
        ];

        for kek_len in [16, 24, 32] {
            let kek: Vec<u8> = (0..kek_len)
                .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
                .collect();

            for plaintext_len in plaintext_lengths {
                let mut patterned_plaintext: Vec<u8> = (0..plaintext_len)
                    .map(|index| (index as u8).wrapping_mul(29).wrapping_add(11))
                    .collect();
                patterned_plaintext[plaintext_len - 1] = 0;

                for plaintext in [patterned_plaintext, vec![0; plaintext_len]] {
                    let (_, ciphertext_len) =
                        validate_plaintext(KeyWrapMode::Rfc5649, plaintext_len).unwrap();
                    let mut ciphertext = vec![0xCC; ciphertext_len];
                    let mut unwrapped = vec![0xCC; ciphertext_len - BLOCK_LEN];

                    wrap_key(KeyWrapMode::Rfc5649, &kek, &plaintext, &mut ciphertext).unwrap();
                    assert_eq!(
                        unwrap_key(KeyWrapMode::Rfc5649, &kek, &ciphertext, &mut unwrapped,),
                        Ok(plaintext_len),
                        "failed for a {kek_len}-byte KEK and {plaintext_len}-byte plaintext"
                    );
                    assert_eq!(&unwrapped[..plaintext_len], plaintext);
                    assert!(unwrapped[plaintext_len..].iter().all(|byte| *byte == 0));
                }
            }
        }
    }

    #[test]
    fn rejects_every_invalid_kek_length_without_touching_output() {
        let plaintext = [0x11; RFC_3394_MIN_PLAINTEXT_LEN];
        let ciphertext = [0x22; RFC_3394_MIN_CIPHERTEXT_LEN];

        for kek_len in [0, 1, 15, 17, 23, 25, 31, 33, 64] {
            let kek = vec![0x33; kek_len];
            let mut wrapped = [0xA5; RFC_3394_MIN_CIPHERTEXT_LEN];
            let mut unwrapped = [0x5A; RFC_3394_MIN_PLAINTEXT_LEN];

            assert_eq!(
                wrap_key(KeyWrapMode::Rfc3394, &kek, &plaintext, &mut wrapped),
                Err(Error::InvalidKekLength { actual: kek_len })
            );
            assert_eq!(wrapped, [0xA5; RFC_3394_MIN_CIPHERTEXT_LEN]);

            assert_eq!(
                unwrap_key(KeyWrapMode::Rfc3394, &kek, &ciphertext, &mut unwrapped,),
                Err(Error::InvalidKekLength { actual: kek_len })
            );
            assert_eq!(unwrapped, [0x5A; RFC_3394_MIN_PLAINTEXT_LEN]);

            wrapped.fill(0xA5);
            unwrapped.fill(0x5A);
            assert_eq!(
                wrap_key(KeyWrapMode::Rfc5649, &kek, &plaintext, &mut wrapped),
                Err(Error::InvalidKekLength { actual: kek_len })
            );
            assert_eq!(wrapped, [0xA5; RFC_3394_MIN_CIPHERTEXT_LEN]);
            assert_eq!(
                unwrap_key(KeyWrapMode::Rfc5649, &kek, &ciphertext, &mut unwrapped,),
                Err(Error::InvalidKekLength { actual: kek_len })
            );
            assert_eq!(unwrapped, [0x5A; RFC_3394_MIN_PLAINTEXT_LEN]);
        }
    }

    #[test]
    fn rejects_invalid_plaintext_lengths_without_touching_output() {
        let kek = [0x44; 16];

        for plaintext_len in [0, 1, 7, 8, 15, 17, 23, 25] {
            let plaintext = vec![0x11; plaintext_len];
            let mut output = [0xA5; 64];

            assert_eq!(
                wrap_key(KeyWrapMode::Rfc3394, &kek, &plaintext, &mut output,),
                Err(Error::InvalidPlaintextLength {
                    mode: KeyWrapMode::Rfc3394,
                    actual: plaintext_len
                })
            );
            assert_eq!(output, [0xA5; 64]);
        }

        let mut output = [0xA5; RFC_5649_MIN_CIPHERTEXT_LEN];
        assert_eq!(
            wrap_key(KeyWrapMode::Rfc5649, &kek, &[], &mut output),
            Err(Error::InvalidPlaintextLength {
                mode: KeyWrapMode::Rfc5649,
                actual: 0,
            })
        );
        assert_eq!(output, [0xA5; RFC_5649_MIN_CIPHERTEXT_LEN]);
    }

    #[test]
    fn rejects_invalid_ciphertext_lengths_without_touching_output() {
        let kek = [0x44; 16];

        for ciphertext_len in [0, 1, 8, 16, 17, 23, 25, 31, 33] {
            let ciphertext = vec![0x22; ciphertext_len];
            let mut output = [0x5A; 64];

            assert_eq!(
                unwrap_key(KeyWrapMode::Rfc3394, &kek, &ciphertext, &mut output,),
                Err(Error::InvalidCiphertextLength {
                    mode: KeyWrapMode::Rfc3394,
                    actual: ciphertext_len
                })
            );
            assert_eq!(output, [0x5A; 64]);
        }

        for ciphertext_len in [0, 1, 8, 15, 17, 23, 25] {
            let ciphertext = vec![0x22; ciphertext_len];
            let mut output = [0x5A; 64];

            assert_eq!(
                unwrap_key(KeyWrapMode::Rfc5649, &kek, &ciphertext, &mut output,),
                Err(Error::InvalidCiphertextLength {
                    mode: KeyWrapMode::Rfc5649,
                    actual: ciphertext_len,
                })
            );
            assert_eq!(output, [0x5A; 64]);
        }
    }

    #[test]
    fn rejects_wrong_output_lengths_without_touching_output() {
        let kek = [0x44; 16];
        let plaintext = [0x11; RFC_3394_MIN_PLAINTEXT_LEN];
        let ciphertext = [0x22; RFC_3394_MIN_CIPHERTEXT_LEN];

        for output_len in [
            0,
            RFC_3394_MIN_CIPHERTEXT_LEN - 1,
            RFC_3394_MIN_CIPHERTEXT_LEN + 1,
        ] {
            let mut output = vec![0xA5; output_len];
            assert_eq!(
                wrap_key(KeyWrapMode::Rfc3394, &kek, &plaintext, &mut output,),
                Err(Error::InvalidOutputLength {
                    expected: RFC_3394_MIN_CIPHERTEXT_LEN,
                    actual: output_len,
                })
            );
            assert!(output.iter().all(|byte| *byte == 0xA5));
        }

        for output_len in [
            0,
            RFC_3394_MIN_PLAINTEXT_LEN - 1,
            RFC_3394_MIN_PLAINTEXT_LEN + 1,
        ] {
            let mut output = vec![0x5A; output_len];
            assert_eq!(
                unwrap_key(KeyWrapMode::Rfc3394, &kek, &ciphertext, &mut output,),
                Err(Error::InvalidOutputLength {
                    expected: RFC_3394_MIN_PLAINTEXT_LEN,
                    actual: output_len,
                })
            );
            assert!(output.iter().all(|byte| *byte == 0x5A));
        }

        let rfc_5649_plaintext = [0x11; BLOCK_LEN - 1];
        let rfc_5649_kek = decode_hex(RFC_5649_VECTORS[1].kek);
        let rfc_5649_ciphertext = decode_hex(RFC_5649_VECTORS[1].ciphertext);

        for output_len in [
            0,
            RFC_5649_MIN_CIPHERTEXT_LEN - 1,
            RFC_5649_MIN_CIPHERTEXT_LEN + 1,
        ] {
            let mut output = vec![0xA5; output_len];
            assert_eq!(
                wrap_key(KeyWrapMode::Rfc5649, &kek, &rfc_5649_plaintext, &mut output,),
                Err(Error::InvalidOutputLength {
                    expected: RFC_5649_MIN_CIPHERTEXT_LEN,
                    actual: output_len,
                })
            );
            assert!(output.iter().all(|byte| *byte == 0xA5));
        }

        for output_len in [0, BLOCK_LEN - 1, BLOCK_LEN + 1] {
            let mut output = vec![0x5A; output_len];
            assert_eq!(
                unwrap_key(
                    KeyWrapMode::Rfc5649,
                    &rfc_5649_kek,
                    &rfc_5649_ciphertext,
                    &mut output,
                ),
                Err(Error::InvalidOutputLength {
                    expected: BLOCK_LEN,
                    actual: output_len,
                })
            );
            assert!(output.iter().all(|byte| *byte == 0x5A));
        }
    }

    #[test]
    fn rejects_each_corrupted_ciphertext_byte_and_zeroizes_output() {
        let vector = &RFC_3394_VECTORS[5];
        let kek = decode_hex(vector.kek);
        let ciphertext = decode_hex(vector.ciphertext);
        let plaintext_len = decode_hex(vector.plaintext).len();

        for corrupted_index in 0..ciphertext.len() {
            let mut corrupted = ciphertext.clone();
            corrupted[corrupted_index] ^= 0x01;
            let mut output = vec![0xD3; plaintext_len];

            assert_eq!(
                unwrap_key(KeyWrapMode::Rfc3394, &kek, &corrupted, &mut output,),
                Err(Error::IntegrityCheckFailed),
                "corruption at ciphertext byte {corrupted_index} was not rejected"
            );
            assert!(
                output.iter().all(|byte| *byte == 0),
                "output was not zeroized after corruption at byte {corrupted_index}"
            );
        }
    }

    #[test]
    fn rejects_wrong_kek_and_zeroizes_output() {
        let vector = &RFC_3394_VECTORS[0];
        let mut wrong_kek = decode_hex(vector.kek);
        wrong_kek[0] ^= 0x80;
        let ciphertext = decode_hex(vector.ciphertext);
        let plaintext_len = decode_hex(vector.plaintext).len();
        let mut output = vec![0xD3; plaintext_len];

        assert_eq!(
            unwrap_key(KeyWrapMode::Rfc3394, &wrong_kek, &ciphertext, &mut output,),
            Err(Error::IntegrityCheckFailed)
        );
        assert!(output.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn enforces_nist_semiblock_limit() {
        let largest_valid_block_count = RFC_3394_MAX_BLOCK_COUNT_EXCLUSIVE - 1;
        assert_eq!(
            checked_step_count(largest_valid_block_count),
            Ok(largest_valid_block_count * ROUNDS as u64)
        );
        assert_eq!(
            checked_step_count(RFC_3394_MAX_BLOCK_COUNT_EXCLUSIVE),
            Err(Error::InputTooLong)
        );
        assert_eq!(
            checked_step_count(RFC_3394_MAX_BLOCK_COUNT_EXCLUSIVE + 1),
            Err(Error::InputTooLong)
        );
        assert_eq!(checked_step_count(u64::MAX), Err(Error::InputTooLong));
    }

    #[test]
    fn enforces_rfc_5649_length_limit_and_checked_sizing() {
        assert_eq!(checked_rfc5649_block_count(0), Ok(0));
        assert_eq!(checked_rfc5649_block_count(1), Ok(1));
        assert_eq!(checked_rfc5649_block_count(8), Ok(1));
        assert_eq!(checked_rfc5649_block_count(9), Ok(2));
        assert_eq!(
            checked_rfc5649_block_count(RFC_5649_MAX_PLAINTEXT_LEN),
            Ok(RFC_5649_MAX_BLOCK_COUNT)
        );
        assert_eq!(
            checked_rfc5649_block_count(RFC_5649_MAX_PLAINTEXT_LEN + 1),
            Err(Error::InputTooLong)
        );
        assert_eq!(
            validate_block_count(
                KeyWrapMode::Rfc5649,
                usize::try_from(RFC_5649_MAX_BLOCK_COUNT).unwrap(),
            ),
            Ok(RFC_5649_MAX_BLOCK_COUNT * ROUNDS as u64)
        );
        assert_eq!(
            validate_block_count(
                KeyWrapMode::Rfc5649,
                usize::try_from(RFC_5649_MAX_BLOCK_COUNT + 1).unwrap(),
            ),
            Err(Error::InputTooLong)
        );
    }

    #[test]
    fn rfc_5649_integrity_validation_checks_prefix_length_and_padding() {
        for padding_len in 0..BLOCK_LEN {
            let plaintext_len = 2 * BLOCK_LEN - padding_len;
            let mut padded_plaintext = [0x11; 2 * BLOCK_LEN];
            padded_plaintext[plaintext_len..].zeroize();
            let register = rfc5649_aiv(plaintext_len);

            assert_eq!(
                validate_rfc5649_integrity(&register, &padded_plaintext),
                Some(plaintext_len)
            );
        }

        let valid_output = [0x11; 2 * BLOCK_LEN];

        let mut wrong_prefix = rfc5649_aiv(valid_output.len());
        wrong_prefix[0] ^= 0x01;
        assert_eq!(
            validate_rfc5649_integrity(&wrong_prefix, &valid_output),
            None
        );

        let too_short_mli = rfc5649_aiv(BLOCK_LEN);
        assert_eq!(
            validate_rfc5649_integrity(&too_short_mli, &valid_output),
            None
        );

        let too_long_mli = rfc5649_aiv(valid_output.len() + 1);
        assert_eq!(
            validate_rfc5649_integrity(&too_long_mli, &valid_output),
            None
        );

        let mut nonzero_padding = [0x11; 2 * BLOCK_LEN];
        let padded_mli = rfc5649_aiv(nonzero_padding.len() - 1);
        nonzero_padding[nonzero_padding.len() - 1] = 0x01;
        assert_eq!(
            validate_rfc5649_integrity(&padded_mli, &nonzero_padding),
            None
        );
    }

    #[test]
    fn errors_have_actionable_messages() {
        let errors = [
            Error::InvalidKekLength { actual: 15 },
            Error::InvalidPlaintextLength {
                mode: KeyWrapMode::Rfc3394,
                actual: 8,
            },
            Error::InvalidCiphertextLength {
                mode: KeyWrapMode::Rfc5649,
                actual: 8,
            },
            Error::InvalidOutputLength {
                expected: 24,
                actual: 23,
            },
            Error::InputTooLong,
            Error::IntegrityCheckFailed,
        ];

        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        assert!(input.len().is_multiple_of(2));
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }
}
