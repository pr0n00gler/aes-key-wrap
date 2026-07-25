# aes-key-wrap

A small, allocation-free implementation of AES Key Wrap from [RFC 3394] and
AES Key Wrap with Padding from [RFC 5649].

Both modes support 128-, 192-, and 256-bit AES key-encryption keys. RFC 3394
accepts plaintext containing at least two 8-byte blocks. RFC 5649 accepts
plaintext from 1 through `2^32-1` bytes and pads it to an 8-byte boundary.

```rust
use aes_key_wrap::{KeyWrapMode, unwrap_key, wrap_key};

let kek = [0x42; 16];
let plaintext = b"wrapped key material";
let mut ciphertext = [0; 32];
let mut recovered = [0; 24];

wrap_key(
    KeyWrapMode::Rfc5649,
    &kek,
    plaintext,
    &mut ciphertext,
)?;
let plaintext_len = unwrap_key(
    KeyWrapMode::Rfc5649,
    &kek,
    &ciphertext,
    &mut recovered,
)?;
assert_eq!(&recovered[..plaintext_len], plaintext);

# Ok::<(), aes_key_wrap::Error>(())
```

The caller must provide an exact-size output buffer:

- RFC 3394 wrapping requires `plaintext.len() + 8` bytes.
- RFC 5649 wrapping requires
  `plaintext.len().div_ceil(8) * 8 + 8` bytes.
- Unwrapping requires `ciphertext.len() - 8` bytes in either mode.

Successful unwrapping returns the authenticated plaintext length. For RFC 5649,
the remaining zero to seven output bytes are verified zero padding. Validation
errors leave the output unchanged; integrity failures zeroize the entire
caller-provided plaintext buffer.

Both algorithms are deterministic, have no nonce or associated data, and
provide approximately a 64-bit integrity check. Applications should supply any
required context binding or replay protection and limit repeated failed unwrap
attempts. The modes use different initial values and do not accept each other's
ciphertext, even when RFC 5649 does not need to add padding.

The minimum supported Rust version is 1.87. Run the test suite with:

```sh
cargo test --all-targets --locked
```

[RFC 3394]: https://www.rfc-editor.org/rfc/rfc3394
[RFC 5649]: https://www.rfc-editor.org/rfc/rfc5649
