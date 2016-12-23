# tokio-openssl

An implementation of SSL streams for Tokio built on top of the [`openssl` crate]

[![Build Status](https://travis-ci.org/alexcrichton//tokio-openssl.svg?branch=master)](https://travis-ci.org/alexcrichton/tokio-openssl)

[Documentation](https://docs.rs/tokio-openssl)
[`openssl` crate]: https://github.com/sfackler/rust-openssl

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
openssl = "0.9"
tokio-openssl = "0.1"
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

`tokio-openssl` is primarily distributed under the terms of both the MIT license
and the Apache License (Version 2.0), with portions covered by various BSD-like
licenses.

See LICENSE-APACHE, and LICENSE-MIT for details.

