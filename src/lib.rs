//! Pure-Rust AES Key Wrap as specified by [RFC 3394].
//!
//! This crate implements the RFC's default `A6A6A6A6A6A6A6A6` initial
//! value. It accepts 128-, 192-, and 256-bit AES key-encryption keys (KEKs).
//! Plaintext must contain at least two 64-bit blocks and does not use padding.
//!
//! The caller supplies the output buffer, so wrapping and unwrapping do not
//! allocate. When ciphertext fails the RFC integrity check, [`unwrap_key`]
//! zeroizes the entire plaintext output buffer before returning an error.
//!
//! # Security considerations
//!
//! AES-KW is deterministic: wrapping the same plaintext with the same KEK
//! produces the same ciphertext. It provides neither a nonce nor associated
//! data, so applications must provide any required context binding, freshness,
//! or replay protection separately. Use an authenticated-encryption scheme
//! instead when nonce-based encryption or associated data is required.
//!
//! The default integrity register provides a 64-bit integrity check. Callers
//! handling attacker-controlled ciphertext should rate-limit or otherwise
//! bound failed unwrap attempts. KEKs should have security strength at least
//! equal to the wrapped material and should be separated across protocols and
//! purposes.
//!
//! This crate implements only the unpadded RFC 3394 profile with its default
//! IV. In particular, it does not implement the padded mode from RFC 5649 or
//! application-defined alternative IVs. Inputs are restricted to the
//! `n < 2^54` semiblock limit specified for AES-KW by [NIST SP 800-38F].
//!
//! [RFC 3394]: https://www.rfc-editor.org/rfc/rfc3394
//! [NIST SP 800-38F]: https://doi.org/10.6028/NIST.SP.800-38F

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::{error, fmt};

use aes::{
    Aes128, Aes192, Aes256,
    cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit, typenum::U16},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const BLOCK_LEN: usize = 8;
const AES_BLOCK_LEN: usize = 16;
const MIN_PLAINTEXT_LEN: usize = 2 * BLOCK_LEN;
const MIN_CIPHERTEXT_LEN: usize = MIN_PLAINTEXT_LEN + BLOCK_LEN;
const DEFAULT_IV: [u8; BLOCK_LEN] = [0xA6; BLOCK_LEN];
const ROUNDS: usize = 6;
const MAX_BLOCK_COUNT_EXCLUSIVE: u64 = 1 << 54;

/// An input validation or integrity error from AES Key Wrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The KEK was not a valid AES key length.
    InvalidKekLength {
        /// Supplied KEK length in bytes.
        actual: usize,
    },

    /// Plaintext was shorter than 16 bytes or not a multiple of 8 bytes.
    InvalidPlaintextLength {
        /// Supplied plaintext length in bytes.
        actual: usize,
    },

    /// Ciphertext was shorter than 24 bytes or not a multiple of 8 bytes.
    InvalidCiphertextLength {
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

    /// The input exceeded NIST SP 800-38F's AES-KW semiblock limit.
    InputTooLong,

    /// The recovered RFC 3394 integrity register did not match the default IV.
    IntegrityCheckFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKekLength { actual } => write!(
                formatter,
                "invalid AES KEK length {actual}; expected 16, 24, or 32 bytes"
            ),
            Self::InvalidPlaintextLength { actual } => write!(
                formatter,
                "invalid plaintext length {actual}; expected a multiple of 8 bytes of at least 16 bytes"
            ),
            Self::InvalidCiphertextLength { actual } => write!(
                formatter,
                "invalid ciphertext length {actual}; expected a multiple of 8 bytes of at least 24 bytes"
            ),
            Self::InvalidOutputLength { expected, actual } => write!(
                formatter,
                "invalid output length {actual}; expected exactly {expected} bytes"
            ),
            Self::InputTooLong => {
                formatter.write_str("input exceeds the NIST SP 800-38F AES-KW length limit")
            }
            Self::IntegrityCheckFailed => {
                formatter.write_str("AES Key Wrap integrity check failed")
            }
        }
    }
}

impl error::Error for Error {}

/// Wraps key data with an AES key-encryption key according to RFC 3394.
///
/// `kek` must be 16, 24, or 32 bytes. `plaintext` must be a multiple of 8
/// bytes and at least 16 bytes long. `output` must be exactly 8 bytes longer
/// than `plaintext`.
///
/// Validation errors leave `output` unchanged.
pub fn wrap_key(kek: &[u8], plaintext: &[u8], output: &mut [u8]) -> Result<(), Error> {
    validate_kek(kek)?;
    let block_count = validate_plaintext(plaintext)?;
    let expected_output_len = plaintext
        .len()
        .checked_add(BLOCK_LEN)
        .ok_or(Error::InputTooLong)?;
    validate_output(output, expected_output_len)?;
    step_count(block_count)?;

    match kek.len() {
        16 => wrap_with(
            &Aes128::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
            plaintext,
            output,
            block_count,
        ),
        24 => wrap_with(
            &Aes192::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
            plaintext,
            output,
            block_count,
        ),
        32 => wrap_with(
            &Aes256::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
            plaintext,
            output,
            block_count,
        ),
        _ => unreachable!("KEK length was validated before cipher construction"),
    }

    Ok(())
}

/// Unwraps RFC 3394 ciphertext with an AES key-encryption key.
///
/// `kek` must be 16, 24, or 32 bytes. `ciphertext` must be a multiple of 8
/// bytes and at least 24 bytes long. `output` must be exactly 8 bytes shorter
/// than `ciphertext`.
///
/// If the RFC integrity check fails, this function zeroizes all of `output`
/// and returns [`Error::IntegrityCheckFailed`] without releasing key data.
/// Input validation errors leave `output` unchanged.
pub fn unwrap_key(kek: &[u8], ciphertext: &[u8], output: &mut [u8]) -> Result<(), Error> {
    validate_kek(kek)?;
    let block_count = validate_ciphertext(ciphertext)?;
    validate_output(output, ciphertext.len() - BLOCK_LEN)?;
    let steps = step_count(block_count)?;

    match kek.len() {
        16 => unwrap_with(
            &Aes128::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
            ciphertext,
            output,
            block_count,
            steps,
        ),
        24 => unwrap_with(
            &Aes192::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
            ciphertext,
            output,
            block_count,
            steps,
        ),
        32 => unwrap_with(
            &Aes256::new_from_slice(kek).map_err(|_| invalid_kek(kek))?,
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

fn validate_plaintext(plaintext: &[u8]) -> Result<usize, Error> {
    if plaintext.len() < MIN_PLAINTEXT_LEN || !plaintext.len().is_multiple_of(BLOCK_LEN) {
        return Err(Error::InvalidPlaintextLength {
            actual: plaintext.len(),
        });
    }

    Ok(plaintext.len() / BLOCK_LEN)
}

fn validate_ciphertext(ciphertext: &[u8]) -> Result<usize, Error> {
    if ciphertext.len() < MIN_CIPHERTEXT_LEN || !ciphertext.len().is_multiple_of(BLOCK_LEN) {
        return Err(Error::InvalidCiphertextLength {
            actual: ciphertext.len(),
        });
    }

    Ok((ciphertext.len() - BLOCK_LEN) / BLOCK_LEN)
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
    if block_count >= MAX_BLOCK_COUNT_EXCLUSIVE {
        return Err(Error::InputTooLong);
    }

    block_count
        .checked_mul(ROUNDS as u64)
        .ok_or(Error::InputTooLong)
}

fn wrap_with<C>(cipher: &C, plaintext: &[u8], output: &mut [u8], block_count: usize)
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    let mut register = Zeroizing::new(DEFAULT_IV);
    let mut block = Zeroizing::new([0u8; AES_BLOCK_LEN]);
    let mut step = 1u64;

    output[BLOCK_LEN..].copy_from_slice(plaintext);

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
    ciphertext: &[u8],
    output: &mut [u8],
    block_count: usize,
    mut step: u64,
) -> Result<(), Error>
where
    C: BlockCipherDecrypt + BlockSizeUser<BlockSize = U16>,
{
    let mut register = Zeroizing::new([0u8; BLOCK_LEN]);
    let mut block = Zeroizing::new([0u8; AES_BLOCK_LEN]);

    register.copy_from_slice(&ciphertext[..BLOCK_LEN]);
    output.copy_from_slice(&ciphertext[BLOCK_LEN..]);

    for _ in (0..ROUNDS).rev() {
        for index in (0..block_count).rev() {
            let offset = index * BLOCK_LEN;
            xor_step(&mut register, step);
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

    if !bool::from(register.as_ref().ct_eq(&DEFAULT_IV)) {
        output.zeroize();
        return Err(Error::IntegrityCheckFailed);
    }

    Ok(())
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

    #[test]
    fn matches_all_rfc_3394_test_vectors() {
        for vector in RFC_3394_VECTORS {
            let kek = decode_hex(vector.kek);
            let plaintext = decode_hex(vector.plaintext);
            let expected_ciphertext = decode_hex(vector.ciphertext);
            let mut ciphertext = vec![0xCC; expected_ciphertext.len()];

            wrap_key(&kek, &plaintext, &mut ciphertext).unwrap();
            assert_eq!(ciphertext, expected_ciphertext);

            let mut unwrapped = vec![0xCC; plaintext.len()];
            unwrap_key(&kek, &ciphertext, &mut unwrapped).unwrap();
            assert_eq!(unwrapped, plaintext);
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

                wrap_key(&kek, &plaintext, &mut ciphertext).unwrap();
                unwrap_key(&kek, &ciphertext, &mut unwrapped).unwrap();

                assert_eq!(unwrapped, plaintext);
            }
        }
    }

    #[test]
    fn rejects_every_invalid_kek_length_without_touching_output() {
        let plaintext = [0x11; MIN_PLAINTEXT_LEN];
        let ciphertext = [0x22; MIN_CIPHERTEXT_LEN];

        for kek_len in [0, 1, 15, 17, 23, 25, 31, 33, 64] {
            let kek = vec![0x33; kek_len];
            let mut wrapped = [0xA5; MIN_CIPHERTEXT_LEN];
            let mut unwrapped = [0x5A; MIN_PLAINTEXT_LEN];

            assert_eq!(
                wrap_key(&kek, &plaintext, &mut wrapped),
                Err(Error::InvalidKekLength { actual: kek_len })
            );
            assert_eq!(wrapped, [0xA5; MIN_CIPHERTEXT_LEN]);

            assert_eq!(
                unwrap_key(&kek, &ciphertext, &mut unwrapped),
                Err(Error::InvalidKekLength { actual: kek_len })
            );
            assert_eq!(unwrapped, [0x5A; MIN_PLAINTEXT_LEN]);
        }
    }

    #[test]
    fn rejects_invalid_plaintext_lengths_without_touching_output() {
        let kek = [0x44; 16];

        for plaintext_len in [0, 1, 7, 8, 15, 17, 23, 25] {
            let plaintext = vec![0x11; plaintext_len];
            let mut output = [0xA5; 64];

            assert_eq!(
                wrap_key(&kek, &plaintext, &mut output),
                Err(Error::InvalidPlaintextLength {
                    actual: plaintext_len
                })
            );
            assert_eq!(output, [0xA5; 64]);
        }
    }

    #[test]
    fn rejects_invalid_ciphertext_lengths_without_touching_output() {
        let kek = [0x44; 16];

        for ciphertext_len in [0, 1, 8, 16, 17, 23, 25, 31, 33] {
            let ciphertext = vec![0x22; ciphertext_len];
            let mut output = [0x5A; 64];

            assert_eq!(
                unwrap_key(&kek, &ciphertext, &mut output),
                Err(Error::InvalidCiphertextLength {
                    actual: ciphertext_len
                })
            );
            assert_eq!(output, [0x5A; 64]);
        }
    }

    #[test]
    fn rejects_wrong_output_lengths_without_touching_output() {
        let kek = [0x44; 16];
        let plaintext = [0x11; MIN_PLAINTEXT_LEN];
        let ciphertext = [0x22; MIN_CIPHERTEXT_LEN];

        for output_len in [0, MIN_CIPHERTEXT_LEN - 1, MIN_CIPHERTEXT_LEN + 1] {
            let mut output = vec![0xA5; output_len];
            assert_eq!(
                wrap_key(&kek, &plaintext, &mut output),
                Err(Error::InvalidOutputLength {
                    expected: MIN_CIPHERTEXT_LEN,
                    actual: output_len,
                })
            );
            assert!(output.iter().all(|byte| *byte == 0xA5));
        }

        for output_len in [0, MIN_PLAINTEXT_LEN - 1, MIN_PLAINTEXT_LEN + 1] {
            let mut output = vec![0x5A; output_len];
            assert_eq!(
                unwrap_key(&kek, &ciphertext, &mut output),
                Err(Error::InvalidOutputLength {
                    expected: MIN_PLAINTEXT_LEN,
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
                unwrap_key(&kek, &corrupted, &mut output),
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
            unwrap_key(&wrong_kek, &ciphertext, &mut output),
            Err(Error::IntegrityCheckFailed)
        );
        assert!(output.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn enforces_nist_semiblock_limit() {
        let largest_valid_block_count = MAX_BLOCK_COUNT_EXCLUSIVE - 1;
        assert_eq!(
            checked_step_count(largest_valid_block_count),
            Ok(largest_valid_block_count * ROUNDS as u64)
        );
        assert_eq!(
            checked_step_count(MAX_BLOCK_COUNT_EXCLUSIVE),
            Err(Error::InputTooLong)
        );
        assert_eq!(
            checked_step_count(MAX_BLOCK_COUNT_EXCLUSIVE + 1),
            Err(Error::InputTooLong)
        );
        assert_eq!(checked_step_count(u64::MAX), Err(Error::InputTooLong));
    }

    #[test]
    fn errors_have_actionable_messages() {
        let errors = [
            Error::InvalidKekLength { actual: 15 },
            Error::InvalidPlaintextLength { actual: 8 },
            Error::InvalidCiphertextLength { actual: 16 },
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
