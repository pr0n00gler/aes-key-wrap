use aes_key_wrap::{Error, unwrap_key, wrap_key};

const SEMIBLOCK_LEN: usize = 8;

#[test]
fn minimum_plaintext_length_round_trips_with_every_aes_key_size() {
    for kek_len in [16, 24, 32] {
        let kek = patterned_bytes(kek_len, 17);
        let plaintext = patterned_bytes(2 * SEMIBLOCK_LEN, 29);
        let ciphertext = wrap(&kek, &plaintext);
        let mut recovered = vec![0; plaintext.len()];

        unwrap_key(&kek, &ciphertext, &mut recovered).unwrap();
        assert_eq!(recovered, plaintext, "failed for a {kek_len}-byte KEK");
    }
}

#[test]
fn rejects_every_single_bit_corruption_and_zeroizes_output() {
    for kek_len in [16, 24, 32] {
        let kek = patterned_bytes(kek_len, 17);
        let plaintext = patterned_bytes(4 * SEMIBLOCK_LEN, 29);
        let ciphertext = wrap(&kek, &plaintext);

        for byte_index in 0..ciphertext.len() {
            for bit_index in 0..8 {
                let mut corrupted = ciphertext.clone();
                corrupted[byte_index] ^= 1 << bit_index;
                assert_integrity_failure_zeroizes(&kek, &corrupted);
            }
        }
    }
}

#[test]
fn rejects_valid_length_structural_corruption_and_zeroizes_output() {
    for kek_len in [16, 24, 32] {
        let kek = patterned_bytes(kek_len, 17);
        let plaintext = patterned_bytes(4 * SEMIBLOCK_LEN, 29);
        let ciphertext = wrap(&kek, &plaintext);

        let truncated = &ciphertext[..ciphertext.len() - SEMIBLOCK_LEN];
        assert_integrity_failure_zeroizes(&kek, truncated);

        let mut extended = ciphertext.clone();
        extended.extend_from_slice(&[0x6B; SEMIBLOCK_LEN]);
        assert_integrity_failure_zeroizes(&kek, &extended);

        let mut reordered = ciphertext.clone();
        reordered[SEMIBLOCK_LEN..3 * SEMIBLOCK_LEN].rotate_left(SEMIBLOCK_LEN);
        assert_integrity_failure_zeroizes(&kek, &reordered);
    }
}

#[test]
fn rejects_wrong_kek_at_every_aes_key_size_and_zeroizes_output() {
    for kek_len in [16, 24, 32] {
        let kek = patterned_bytes(kek_len, 17);
        let plaintext = patterned_bytes(2 * SEMIBLOCK_LEN, 29);
        let ciphertext = wrap(&kek, &plaintext);
        let mut wrong_kek = kek;
        wrong_kek[kek_len - 1] ^= 0x80;

        assert_integrity_failure_zeroizes(&wrong_kek, &ciphertext);
    }
}

fn wrap(kek: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = vec![0; plaintext.len() + SEMIBLOCK_LEN];
    wrap_key(kek, plaintext, &mut ciphertext).unwrap();
    ciphertext
}

fn assert_integrity_failure_zeroizes(kek: &[u8], ciphertext: &[u8]) {
    let mut output = vec![0xD3; ciphertext.len() - SEMIBLOCK_LEN];
    assert_eq!(
        unwrap_key(kek, ciphertext, &mut output),
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
