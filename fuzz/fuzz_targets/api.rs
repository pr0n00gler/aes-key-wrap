#![no_main]

use aes_key_wrap::{Error, KeyWrapMode, unwrap_key, wrap_key};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 4096;
const SENTINEL: u8 = 0xD3;

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(MAX_INPUT_LEN)];
    let Some((&selector, remainder)) = input.split_first() else {
        return;
    };
    let kek_len = match selector & 0b11 {
        0 => 16,
        1 => 24,
        2 => 32,
        _ => 15,
    };
    let kek: Vec<u8> = (0..kek_len)
        .map(|index| {
            remainder
                .get(index)
                .copied()
                .unwrap_or((index as u8).wrapping_mul(17))
        })
        .collect();
    let mode = if selector & 0b100 == 0 {
        KeyWrapMode::Rfc3394
    } else {
        KeyWrapMode::Rfc5649
    };

    exercise_wrap(mode, &kek, remainder);
    exercise_unwrap(mode, &kek, remainder);
});

fn exercise_wrap(mode: KeyWrapMode, kek: &[u8], plaintext: &[u8]) {
    let ciphertext_len = match mode {
        KeyWrapMode::Rfc3394 => plaintext.len() + 8,
        KeyWrapMode::Rfc5649 => plaintext.len().div_ceil(8) * 8 + 8,
    };
    let mut ciphertext = vec![SENTINEL; ciphertext_len];
    match wrap_key(mode, kek, plaintext, &mut ciphertext) {
        Ok(()) => {
            let mut recovered = vec![SENTINEL; ciphertext.len() - 8];
            let plaintext_len = unwrap_key(mode, kek, &ciphertext, &mut recovered)
                .expect("every successfully wrapped value must unwrap");
            assert_eq!(plaintext_len, plaintext.len());
            assert_eq!(&recovered[..plaintext_len], plaintext);
            assert!(recovered[plaintext_len..].iter().all(|byte| *byte == 0));
        }
        Err(_) => assert!(
            ciphertext.iter().all(|byte| *byte == SENTINEL),
            "a wrap validation error modified output"
        ),
    }
}

fn exercise_unwrap(mode: KeyWrapMode, kek: &[u8], ciphertext: &[u8]) {
    let mut plaintext = vec![SENTINEL; ciphertext.len().saturating_sub(8)];
    match unwrap_key(mode, kek, ciphertext, &mut plaintext) {
        Ok(plaintext_len) => {
            assert!(plaintext[plaintext_len..].iter().all(|byte| *byte == 0));
            let mut rewrapped = vec![SENTINEL; ciphertext.len()];
            wrap_key(mode, kek, &plaintext[..plaintext_len], &mut rewrapped)
                .expect("every successfully unwrapped value must wrap");
            assert_eq!(rewrapped, ciphertext);
        }
        Err(Error::IntegrityCheckFailed) => assert!(
            plaintext.iter().all(|byte| *byte == 0),
            "an integrity failure exposed plaintext"
        ),
        Err(_) => assert!(
            plaintext.iter().all(|byte| *byte == SENTINEL),
            "an unwrap validation error modified output"
        ),
    }
}
