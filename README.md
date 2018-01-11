# tokio-openssl

An implementation of SSL streams for Tokio built on top of the [`openssl` crate]

[![Build Status](https://travis-ci.org/alexcrichton//tokio-openssl.svg?branch=master)](https://travis-ci.org/alexcrichton/tokio-openssl)

[Documentation](https://docs.rs/tokio-openssl)

[`openssl` crate]: https://github.com/sfackler/rust-openssl

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
openssl = "0.10"
tokio-openssl = "0.2"
```

Next, add this to your crate:

```rust
extern crate openssl;
extern crate tokio_openssl;

use tokio_openssl::{SslConnectorExt, SslAcceptorExt};
```

This crate provides two extension traits, `SslConnectorExt` and
`SslAcceptorExt`, which augment the functionality provided by the [`openssl`
crate]. These extension traits provide the ability to connect a stream
asynchronously and accept a socket asynchronously. Configuration of OpenSSL
parameters is still done through the support in the `openssl` crate.


# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Serde by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
