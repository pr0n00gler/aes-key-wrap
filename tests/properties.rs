use aes_key_wrap::{KeyWrapMode, unwrap_key, wrap_key};
use aes_kw::{KeyInit, KwAes128, KwAes192, KwAes256, KwpAes128, KwpAes192, KwpAes256};
use proptest::prelude::*;

const SEMIBLOCK_LEN: usize = 8;

prop_compose! {
    fn valid_rfc_3394_input()
        (
            kek_len in prop_oneof![Just(16usize), Just(24usize), Just(32usize)],
            block_count in 2usize..=128,
        )
        (
            kek in prop::collection::vec(any::<u8>(), kek_len),
            plaintext in prop::collection::vec(any::<u8>(), block_count * SEMIBLOCK_LEN),
        )
        -> (Vec<u8>, Vec<u8>)
    {
        (kek, plaintext)
    }
}

prop_compose! {
    fn valid_rfc_5649_input()
        (
            kek_len in prop_oneof![Just(16usize), Just(24usize), Just(32usize)],
            plaintext_len in prop_oneof![
                4 => 1usize..=17,
                1 => Just(20usize),
                1 => Just(24usize),
                1 => Just(31usize),
                1 => Just(32usize),
                1 => Just(33usize),
                4 => 18usize..=1024,
            ],
        )
        (
            kek in prop::collection::vec(any::<u8>(), kek_len),
            plaintext in prop::collection::vec(any::<u8>(), plaintext_len),
        )
        -> (Vec<u8>, Vec<u8>)
    {
        (kek, plaintext)
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn rfc_3394_agrees_with_independent_rustcrypto_implementation(
        (kek, plaintext) in valid_rfc_3394_input(),
    ) {
        let expected = rustcrypto_kw_wrap(&kek, &plaintext);
        let mut ciphertext = vec![0; plaintext.len() + SEMIBLOCK_LEN];
        wrap_key(KeyWrapMode::Rfc3394, &kek, &plaintext, &mut ciphertext).unwrap();
        prop_assert_eq!(&ciphertext, &expected);

        let mut recovered = vec![0; plaintext.len()];
        let plaintext_len =
            unwrap_key(KeyWrapMode::Rfc3394, &kek, &expected, &mut recovered).unwrap();
        prop_assert_eq!(plaintext_len, plaintext.len());
        prop_assert_eq!(&recovered, &plaintext);

        let mut second_ciphertext = vec![0; ciphertext.len()];
        wrap_key(
            KeyWrapMode::Rfc3394,
            &kek,
            &recovered,
            &mut second_ciphertext,
        )
        .unwrap();
        prop_assert_eq!(second_ciphertext, ciphertext);
    }

    #[test]
    fn rfc_5649_agrees_with_independent_rustcrypto_implementation(
        (kek, plaintext) in valid_rfc_5649_input(),
    ) {
        let expected = rustcrypto_kwp_wrap(&kek, &plaintext);
        let mut ciphertext = vec![
            0;
            plaintext.len().div_ceil(SEMIBLOCK_LEN) * SEMIBLOCK_LEN + SEMIBLOCK_LEN
        ];
        wrap_key(KeyWrapMode::Rfc5649, &kek, &plaintext, &mut ciphertext).unwrap();
        prop_assert_eq!(&ciphertext, &expected);

        let mut recovered = vec![0xD3; expected.len() - SEMIBLOCK_LEN];
        let plaintext_len =
            unwrap_key(KeyWrapMode::Rfc5649, &kek, &expected, &mut recovered).unwrap();
        prop_assert_eq!(plaintext_len, plaintext.len());
        prop_assert_eq!(&recovered[..plaintext_len], &plaintext);
        prop_assert!(recovered[plaintext_len..].iter().all(|byte| *byte == 0));

        let mut second_ciphertext = vec![0; ciphertext.len()];
        wrap_key(
            KeyWrapMode::Rfc5649,
            &kek,
            &recovered[..plaintext_len],
            &mut second_ciphertext,
        )
        .unwrap();
        prop_assert_eq!(second_ciphertext, ciphertext);
    }
}

fn rustcrypto_kw_wrap(kek: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut output = vec![0; plaintext.len() + SEMIBLOCK_LEN];

    match kek.len() {
        16 => {
            KwAes128::new_from_slice(kek)
                .unwrap()
                .wrap_key(plaintext, &mut output)
                .unwrap();
        }
        24 => {
            KwAes192::new_from_slice(kek)
                .unwrap()
                .wrap_key(plaintext, &mut output)
                .unwrap();
        }
        32 => {
            KwAes256::new_from_slice(kek)
                .unwrap()
                .wrap_key(plaintext, &mut output)
                .unwrap();
        }
        _ => unreachable!("the property strategy only emits valid AES key sizes"),
    }

    output
}

fn rustcrypto_kwp_wrap(kek: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut output =
        vec![0; plaintext.len().div_ceil(SEMIBLOCK_LEN) * SEMIBLOCK_LEN + SEMIBLOCK_LEN];

    match kek.len() {
        16 => {
            KwpAes128::new_from_slice(kek)
                .unwrap()
                .wrap_key(plaintext, &mut output)
                .unwrap();
        }
        24 => {
            KwpAes192::new_from_slice(kek)
                .unwrap()
                .wrap_key(plaintext, &mut output)
                .unwrap();
        }
        32 => {
            KwpAes256::new_from_slice(kek)
                .unwrap()
                .wrap_key(plaintext, &mut output)
                .unwrap();
        }
        _ => unreachable!("the property strategy only emits valid AES key sizes"),
    }

    output
}
