use aes_key_wrap::{unwrap_key, wrap_key};
use aes_kw::{KeyInit, KwAes128, KwAes192, KwAes256};
use proptest::prelude::*;

const SEMIBLOCK_LEN: usize = 8;

prop_compose! {
    fn valid_input()
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn agrees_with_independent_rustcrypto_implementation(
        (kek, plaintext) in valid_input(),
    ) {
        let expected = rustcrypto_wrap(&kek, &plaintext);
        let mut ciphertext = vec![0; plaintext.len() + SEMIBLOCK_LEN];
        wrap_key(&kek, &plaintext, &mut ciphertext).unwrap();
        prop_assert_eq!(&ciphertext, &expected);

        let mut recovered = vec![0; plaintext.len()];
        unwrap_key(&kek, &expected, &mut recovered).unwrap();
        prop_assert_eq!(&recovered, &plaintext);

        let mut second_ciphertext = vec![0; ciphertext.len()];
        wrap_key(&kek, &recovered, &mut second_ciphertext).unwrap();
        prop_assert_eq!(second_ciphertext, ciphertext);
    }
}

fn rustcrypto_wrap(kek: &[u8], plaintext: &[u8]) -> Vec<u8> {
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
