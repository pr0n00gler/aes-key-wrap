# aes-key-wrap

A small, allocation-free implementation of AES Key Wrap using the default
initial value from [RFC 3394].

It supports 128-, 192-, and 256-bit AES key-encryption keys. Plaintext must be
at least 16 bytes and a multiple of 8 bytes. RFC 5649 padding and custom initial
values are not supported.

```rust
use aes_key_wrap::{unwrap_key, wrap_key};

let kek = [0x42; 16];
let plaintext = [0x11; 16];
let mut ciphertext = [0; 24];
let mut recovered = [0; 16];

wrap_key(&kek, &plaintext, &mut ciphertext)?;
unwrap_key(&kek, &ciphertext, &mut recovered)?;
assert_eq!(recovered, plaintext);

# Ok::<(), aes_key_wrap::Error>(())
```

AES-KW is deterministic, has no nonce or associated data, and provides a
64-bit integrity check. Applications should provide any required context
binding or replay protection and should limit repeated failed unwrap attempts.
Integrity failures zeroize the entire caller-provided plaintext output buffer.

The minimum supported Rust version is 1.87. Run the test suite with:

```sh
cargo test --all-targets --locked
```

[RFC 3394]: https://www.rfc-editor.org/rfc/rfc3394
