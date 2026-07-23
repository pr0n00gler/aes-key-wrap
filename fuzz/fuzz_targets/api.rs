#![no_main]

use aes_key_wrap::{Error, unwrap_key, wrap_key};
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

    exercise_wrap(&kek, remainder);
    exercise_unwrap(&kek, remainder);
});

fn exercise_wrap(kek: &[u8], plaintext: &[u8]) {
    let mut ciphertext = vec![SENTINEL; plaintext.len() + 8];
    match wrap_key(kek, plaintext, &mut ciphertext) {
        Ok(()) => {
            let mut recovered = vec![SENTINEL; plaintext.len()];
            unwrap_key(kek, &ciphertext, &mut recovered)
                .expect("every successfully wrapped value must unwrap");
            assert_eq!(recovered, plaintext);
        }
        Err(_) => assert!(
            ciphertext.iter().all(|byte| *byte == SENTINEL),
            "a wrap validation error modified output"
        ),
    }
}

fn exercise_unwrap(kek: &[u8], ciphertext: &[u8]) {
    let mut plaintext = vec![SENTINEL; ciphertext.len().saturating_sub(8)];
    match unwrap_key(kek, ciphertext, &mut plaintext) {
        Ok(()) => {
            let mut rewrapped = vec![SENTINEL; ciphertext.len()];
            wrap_key(kek, &plaintext, &mut rewrapped)
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
