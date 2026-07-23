use aes_key_wrap::{Error, unwrap_key, wrap_key};
use wycheproof::{
    TestResult,
    keywrap::{TestName, TestSet},
};

const SENTINEL: u8 = 0xD3;

#[test]
fn passes_google_wycheproof_aes_wrap_vectors() {
    let test_set = TestSet::load(TestName::AesKeyWrap).expect("embedded vectors should parse");
    let mut test_count = 0;
    let mut long_counter_cases = 0;

    for group in &test_set.test_groups {
        for test in &group.tests {
            test_count += 1;
            assert_eq!(
                test.key.len() * 8,
                group.key_size,
                "tcId {} has inconsistent KEK metadata",
                test.tc_id
            );

            match test.result {
                TestResult::Valid => {
                    let mut ciphertext = vec![SENTINEL; test.ct.len()];
                    wrap_key(&test.key, &test.pt, &mut ciphertext)
                        .unwrap_or_else(|error| panic!("tcId {} wrap failed: {error}", test.tc_id));
                    assert_eq!(
                        ciphertext.as_slice(),
                        test.ct.as_slice(),
                        "tcId {} wrap did not match the published ciphertext",
                        test.tc_id
                    );

                    let mut plaintext = vec![SENTINEL; test.pt.len()];
                    unwrap_key(&test.key, &test.ct, &mut plaintext).unwrap_or_else(|error| {
                        panic!("tcId {} unwrap failed: {error}", test.tc_id)
                    });
                    assert_eq!(
                        plaintext.as_slice(),
                        test.pt.as_slice(),
                        "tcId {} recovered the wrong plaintext",
                        test.tc_id
                    );

                    if test.comment == "Round counter larger than 256" {
                        assert!(
                            test.pt.len() / 8 > 42,
                            "the counter regression vector must cross 0xff"
                        );
                        long_counter_cases += 1;
                    }
                }
                TestResult::Invalid => {
                    let mut plaintext = vec![SENTINEL; test.ct.len().saturating_sub(8)];
                    let result = unwrap_key(&test.key, &test.ct, &mut plaintext);
                    let error = result.unwrap_err_or_else(test.tc_id);

                    if error == Error::IntegrityCheckFailed {
                        assert!(
                            plaintext.iter().all(|byte| *byte == 0),
                            "tcId {} exposed plaintext after an integrity failure",
                            test.tc_id
                        );
                    } else {
                        assert!(
                            plaintext.iter().all(|byte| *byte == SENTINEL),
                            "tcId {} modified output after a validation error",
                            test.tc_id
                        );
                    }
                }
                TestResult::Acceptable => {
                    let mut ciphertext = vec![SENTINEL; test.ct.len()];
                    assert_eq!(
                        wrap_key(&test.key, &test.pt, &mut ciphertext),
                        Err(Error::InvalidPlaintextLength {
                            actual: test.pt.len()
                        }),
                        "tcId {} should be rejected by the RFC 3394 n >= 2 profile",
                        test.tc_id
                    );
                    assert!(ciphertext.iter().all(|byte| *byte == SENTINEL));

                    let mut plaintext = vec![SENTINEL; test.pt.len()];
                    assert_eq!(
                        unwrap_key(&test.key, &test.ct, &mut plaintext),
                        Err(Error::InvalidCiphertextLength {
                            actual: test.ct.len()
                        }),
                        "tcId {} should be rejected by the RFC 3394 n >= 2 profile",
                        test.tc_id
                    );
                    assert!(plaintext.iter().all(|byte| *byte == SENTINEL));
                }
            }
        }
    }

    assert_eq!(test_count, test_set.number_of_tests);
    assert_eq!(
        long_counter_cases, 3,
        "expected one >42-block vector for each AES KEK size"
    );
}

trait ResultTestExt {
    fn unwrap_err_or_else(self, test_id: usize) -> Error;
}

impl ResultTestExt for Result<(), Error> {
    fn unwrap_err_or_else(self, test_id: usize) -> Error {
        match self {
            Ok(()) => panic!("tcId {test_id} accepted an invalid ciphertext"),
            Err(error) => error,
        }
    }
}
