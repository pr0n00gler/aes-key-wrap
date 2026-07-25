use aes_key_wrap::{Error, KeyWrapMode, unwrap_key, wrap_key};

const SEMIBLOCK_LEN: usize = 8;

#[test]
fn minimum_plaintext_lengths_round_trip_with_every_aes_key_size() {
    for kek_len in [16, 24, 32] {
        let kek = patterned_bytes(kek_len, 17);

        for (mode, plaintext_len) in [
            (KeyWrapMode::Rfc3394, 2 * SEMIBLOCK_LEN),
            (KeyWrapMode::Rfc5649, 1),
            (KeyWrapMode::Rfc5649, SEMIBLOCK_LEN),
            (KeyWrapMode::Rfc5649, SEMIBLOCK_LEN + 1),
        ] {
            let plaintext = patterned_bytes(plaintext_len, 29);
            let ciphertext = wrap(mode, &kek, &plaintext);
            let mut recovered = vec![0xD3; ciphertext.len() - SEMIBLOCK_LEN];

            assert_eq!(
                unwrap_key(mode, &kek, &ciphertext, &mut recovered),
                Ok(plaintext.len()),
                "failed for {mode} with a {kek_len}-byte KEK"
            );
            assert_eq!(&recovered[..plaintext.len()], plaintext);
            assert!(recovered[plaintext.len()..].iter().all(|byte| *byte == 0));
        }
    }
}

#[test]
fn rejects_every_single_bit_corruption_and_zeroizes_output() {
    for kek_len in [16, 24, 32] {
        let kek = patterned_bytes(kek_len, 17);

        for (mode, plaintext_len) in [
            (KeyWrapMode::Rfc3394, 4 * SEMIBLOCK_LEN),
            (KeyWrapMode::Rfc5649, 7),
            (KeyWrapMode::Rfc5649, 20),
        ] {
            let plaintext = patterned_bytes(plaintext_len, 29);
            let ciphertext = wrap(mode, &kek, &plaintext);

            for byte_index in 0..ciphertext.len() {
                for bit_index in 0..8 {
                    let mut corrupted = ciphertext.clone();
                    corrupted[byte_index] ^= 1 << bit_index;
                    assert_integrity_failure_zeroizes(mode, &kek, &corrupted);
                }
            }
        }
    }
}

#[test]
fn rejects_valid_length_structural_corruption_and_zeroizes_output() {
    for kek_len in [16, 24, 32] {
        let kek = patterned_bytes(kek_len, 17);

        for (mode, plaintext_len) in [
            (KeyWrapMode::Rfc3394, 4 * SEMIBLOCK_LEN),
            (KeyWrapMode::Rfc5649, 25),
        ] {
            let plaintext = patterned_bytes(plaintext_len, 29);
            let ciphertext = wrap(mode, &kek, &plaintext);

            let truncated = &ciphertext[..ciphertext.len() - SEMIBLOCK_LEN];
            assert_integrity_failure_zeroizes(mode, &kek, truncated);

            let mut extended = ciphertext.clone();
            extended.extend_from_slice(&[0x6B; SEMIBLOCK_LEN]);
            assert_integrity_failure_zeroizes(mode, &kek, &extended);

            let mut reordered = ciphertext.clone();
            reordered[SEMIBLOCK_LEN..3 * SEMIBLOCK_LEN].rotate_left(SEMIBLOCK_LEN);
            assert_integrity_failure_zeroizes(mode, &kek, &reordered);
        }
    }
}

#[test]
fn rejects_wrong_kek_at_every_aes_key_size_and_zeroizes_output() {
    for kek_len in [16, 24, 32] {
        let kek = patterned_bytes(kek_len, 17);

        for (mode, plaintext_len) in [
            (KeyWrapMode::Rfc3394, 2 * SEMIBLOCK_LEN),
            (KeyWrapMode::Rfc5649, 7),
            (KeyWrapMode::Rfc5649, 20),
        ] {
            let plaintext = patterned_bytes(plaintext_len, 29);
            let ciphertext = wrap(mode, &kek, &plaintext);
            let mut wrong_kek = kek.clone();
            wrong_kek[kek_len - 1] ^= 0x80;

            assert_integrity_failure_zeroizes(mode, &wrong_kek, &ciphertext);
        }
    }
}

#[test]
fn modes_reject_each_others_ciphertext_even_when_no_padding_is_needed() {
    let kek = patterned_bytes(32, 17);
    let plaintext = patterned_bytes(2 * SEMIBLOCK_LEN, 29);
    let rfc_3394_ciphertext = wrap(KeyWrapMode::Rfc3394, &kek, &plaintext);
    let rfc_5649_ciphertext = wrap(KeyWrapMode::Rfc5649, &kek, &plaintext);

    assert_ne!(rfc_3394_ciphertext, rfc_5649_ciphertext);
    assert_integrity_failure_zeroizes(KeyWrapMode::Rfc5649, &kek, &rfc_3394_ciphertext);
    assert_integrity_failure_zeroizes(KeyWrapMode::Rfc3394, &kek, &rfc_5649_ciphertext);
}

fn wrap(mode: KeyWrapMode, kek: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let ciphertext_len = match mode {
        KeyWrapMode::Rfc3394 => plaintext.len() + SEMIBLOCK_LEN,
        KeyWrapMode::Rfc5649 => {
            plaintext.len().div_ceil(SEMIBLOCK_LEN) * SEMIBLOCK_LEN + SEMIBLOCK_LEN
        }
    };
    let mut ciphertext = vec![0; ciphertext_len];
    wrap_key(mode, kek, plaintext, &mut ciphertext).unwrap();
    ciphertext
}

fn assert_integrity_failure_zeroizes(mode: KeyWrapMode, kek: &[u8], ciphertext: &[u8]) {
    let mut output = vec![0xD3; ciphertext.len() - SEMIBLOCK_LEN];
    assert_eq!(
        unwrap_key(mode, kek, ciphertext, &mut output),
        Err(Error::IntegrityCheckFailed)
    );
    assert!(
        output.iter().all(|byte| *byte == 0),
        "plaintext output was not zeroized"
    );
}

fn patterned_bytes(len: usize, multiplier: u8) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(multiplier).wrapping_add(11))
        .collect()
}
