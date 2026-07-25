use aes_key_wrap::{Error, KeyWrapMode, unwrap_key, wrap_key};
use wycheproof::{
    TestResult,
    keywrap::{TestName, TestSet},
};

const SENTINEL: u8 = 0xD3;
const SEMIBLOCK_LEN: usize = 8;

#[test]
fn passes_google_wycheproof_aes_wrap_vectors() {
    let stats = run_test_set(TestName::AesKeyWrap, KeyWrapMode::Rfc3394);

    assert_eq!(stats.long_counter_cases, 3);
    assert!(stats.valid_cases > 0);
    assert!(stats.invalid_cases > 0);
    assert!(stats.acceptable_cases > 0);
}

#[test]
fn passes_all_google_wycheproof_aes_kwp_vectors() {
    let stats = run_test_set(TestName::AesKeyWrapWithPadding, KeyWrapMode::Rfc5649);

    assert_eq!(stats.total, 254);
    assert_eq!(stats.valid_cases, 77);
    assert_eq!(stats.invalid_cases, 177);
    assert_eq!(stats.acceptable_cases, 0);
    assert_eq!(stats.long_counter_cases, 3);
}

#[derive(Default)]
struct Stats {
    total: usize,
    valid_cases: usize,
    invalid_cases: usize,
    acceptable_cases: usize,
    long_counter_cases: usize,
}

fn run_test_set(test_name: TestName, mode: KeyWrapMode) -> Stats {
    let test_set = TestSet::load(test_name).expect("embedded vectors should parse");
    let mut stats = Stats::default();

    for group in &test_set.test_groups {
        for test in &group.tests {
            stats.total += 1;
            assert_eq!(
                test.key.len() * 8,
                group.key_size,
                "tcId {} has inconsistent KEK metadata",
                test.tc_id
            );

            match test.result {
                TestResult::Valid => {
                    stats.valid_cases += 1;
                    let mut ciphertext = vec![SENTINEL; test.ct.len()];
                    wrap_key(mode, &test.key, &test.pt, &mut ciphertext)
                        .unwrap_or_else(|error| panic!("tcId {} wrap failed: {error}", test.tc_id));
                    assert_eq!(
                        ciphertext.as_slice(),
                        test.ct.as_slice(),
                        "tcId {} wrap did not match the published ciphertext",
                        test.tc_id
                    );

                    let mut plaintext = vec![SENTINEL; test.ct.len().saturating_sub(SEMIBLOCK_LEN)];
                    let plaintext_len = unwrap_key(mode, &test.key, &test.ct, &mut plaintext)
                        .unwrap_or_else(|error| {
                            panic!("tcId {} unwrap failed: {error}", test.tc_id)
                        });
                    assert_eq!(
                        plaintext_len,
                        test.pt.len(),
                        "tcId {} returned the wrong authenticated length",
                        test.tc_id
                    );
                    assert_eq!(
                        &plaintext[..plaintext_len],
                        test.pt.as_slice(),
                        "tcId {} recovered the wrong plaintext",
                        test.tc_id
                    );
                    assert!(
                        plaintext[plaintext_len..].iter().all(|byte| *byte == 0),
                        "tcId {} left nonzero authenticated padding",
                        test.tc_id
                    );

                    if test.comment.starts_with("Round counter") {
                        assert!(
                            test.pt.len() / SEMIBLOCK_LEN > 42,
                            "the counter regression vector must cross 0xff"
                        );
                        stats.long_counter_cases += 1;
                    }
                }
                TestResult::Invalid => {
                    stats.invalid_cases += 1;
                    let mut plaintext = vec![SENTINEL; test.ct.len().saturating_sub(SEMIBLOCK_LEN)];
                    let error = unwrap_key(mode, &test.key, &test.ct, &mut plaintext)
                        .unwrap_err_or_else(test.tc_id);

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
                    stats.acceptable_cases += 1;
                    assert_eq!(mode, KeyWrapMode::Rfc3394);

                    let mut ciphertext = vec![SENTINEL; test.ct.len()];
                    assert_eq!(
                        wrap_key(mode, &test.key, &test.pt, &mut ciphertext),
                        Err(Error::InvalidPlaintextLength {
                            mode,
                            actual: test.pt.len(),
                        }),
                        "tcId {} should be rejected by the RFC 3394 n >= 2 profile",
                        test.tc_id
                    );
                    assert!(ciphertext.iter().all(|byte| *byte == SENTINEL));

                    let mut plaintext = vec![SENTINEL; test.pt.len()];
                    assert_eq!(
                        unwrap_key(mode, &test.key, &test.ct, &mut plaintext),
                        Err(Error::InvalidCiphertextLength {
                            mode,
                            actual: test.ct.len(),
                        }),
                        "tcId {} should be rejected by the RFC 3394 n >= 2 profile",
                        test.tc_id
                    );
                    assert!(plaintext.iter().all(|byte| *byte == SENTINEL));
                }
            }
        }
    }

    assert_eq!(stats.total, test_set.number_of_tests);
    stats
}

trait ResultTestExt {
    fn unwrap_err_or_else(self, test_id: usize) -> Error;
}

impl ResultTestExt for Result<usize, Error> {
    fn unwrap_err_or_else(self, test_id: usize) -> Error {
        match self {
            Ok(_) => panic!("tcId {test_id} accepted an invalid ciphertext"),
            Err(error) => error,
        }
    }
}
