//! Async TLS streams backed by OpenSSL
//!
//! This library is an implementation of TLS streams using OpenSSL for
//! negotiating the connection. Each TLS stream implements the `Read` and
//! `Write` traits to interact and interoperate with the rest of the futures I/O
//! ecosystem. Client connections initiated from this crate verify hostnames
//! automatically and by default.
//!
//! This crate primarily exports this ability through two extension traits,
//! `SslConnectorExt` and `SslAcceptorExt`. These traits augment the
//! functionality provided by the `openssl` crate, on which this crate is
//! built. Configuration of TLS parameters is still primarily done through the
//! `openssl` crate.

#![deny(missing_docs)]

extern crate futures;
extern crate openssl;
extern crate tokio_io;

use futures::{Poll, Future, Async};
use openssl::ssl::{self, SslAcceptor, SslConnector, ConnectConfiguration, HandshakeError,
                   ShutdownResult, ErrorCode, MidHandshakeSslStream};
use std::io::{self, Read, Write};
use std::mem;
use tokio_io::{AsyncRead, AsyncWrite};

/// A wrapper around an underlying raw stream which implements the SSL
/// protocol.
///
/// A `SslStream<S>` represents a handshake that has been completed successfully
/// and both the server and the client are ready for receiving and sending
/// data. Bytes read from a `SslStream` are decrypted from `S` and bytes written
/// to a `SslStream` are encrypted when passing through to `S`.
#[derive(Debug)]
pub struct SslStream<S> {
    inner: ssl::SslStream<S>,
}

/// Future returned from `SslConnectorExt::connect_async` which will resolve
/// once the connection handshake has finished.
pub struct ConnectAsync<S>(ConnectAsyncInner<S>);

enum ConnectAsyncInner<S> {
    Start {
        config: ConnectConfiguration,
        domain: String,
        stream: S,
    },
    Handshake(MidHandshakeSslStream<S>),
    Error(HandshakeError<S>),
    Done,
}

/// Future returned from `SslAcceptorExt::accept_async` which will resolve
/// once the accept handshake has finished.
pub struct AcceptAsync<S>(AcceptAsyncInner<S>);

enum AcceptAsyncInner<S> {
    Start {
        acceptor: SslAcceptor,
        stream: S,
    },
    Handshake(MidHandshakeSslStream<S>),
    Done,
}

/// Extension trait for the `SslConnector` type in the `openssl` crate.
pub trait SslConnectorExt {
    /// Connects the provided stream with this connector, assuming the provided
    /// domain.
    ///
    /// This function will internally call `SslConnector::connect` to connect
    /// the stream and returns a future representing the resolution of the
    /// connection operation. The returned future will resolve to either
    /// `SslStream<S>` or `HandshakeError` depending if it's successful or not.
    ///
    /// This is typically used for clients who have already established, for
    /// example, a TCP connection to a remote server. That stream is then
    /// provided here to perform the client half of a connection to a
    /// TLS-powered server.
    // TODO change to AsyncRead/Write on major bump all throughout this file
    fn connect_async<S>(&self, domain: &str, stream: S) -> ConnectAsync<S>
        where S: AsyncRead + AsyncWrite;
}

/// Extension trait for the `ConnectConfiguration` type in the `openssl` crate.
pub trait ConnectConfigurationExt {
    /// Connects the provided stream with this connector, assuming the provided
    /// domain.
    ///
    /// This function will internally call `ConnectConfiguration::connect` to
    /// connect the stream and returns a future representing the resolution of
    /// the connection operation. The returned future will resolve to either
    /// `SslStream<S>` or `HandshakeError` depending if it's successful or not.
    ///
    /// This is typically used for clients who have already established, for
    /// example, a TCP connection to a remote server. That stream is then
    /// provided here to perform the client half of a connection to a
    /// TLS-powered server.
    // TODO change to AsyncRead/Write on major bump all throughout this file
    fn connect_async<S>(self, domain: &str, stream: S) -> ConnectAsync<S>
        where S: AsyncRead + AsyncWrite;
}

/// Extension trait for the `SslAcceptor` type in the `openssl` crate.
pub trait SslAcceptorExt {
    /// Accepts a new client connection with the provided stream.
    ///
    /// This function will internally call `SslAcceptor::accept` to connect
    /// the stream and returns a future representing the resolution of the
    /// connection operation. The returned future will resolve to either
    /// `SslStream<S>` or `HandshakeError` depending if it's successful or not.
    ///
    /// This is typically used after a new socket has been accepted from a
    /// `TcpListener`. That socket is then passed to this function to perform
    /// the server half of accepting a client connection.
    fn accept_async<S>(&self, stream: S) -> AcceptAsync<S>
        where S: AsyncRead + AsyncWrite;
}

impl<S> SslStream<S> {
    /// Get access to the internal `openssl::SslStream` stream which also
    /// transitively allows access to `S`.
    pub fn get_ref(&self) -> &ssl::SslStream<S> {
        &self.inner
    }

    /// Get mutable access to the internal `openssl::SslStream` stream which
    /// also transitively allows mutable access to `S`.
    pub fn get_mut(&mut self) -> &mut ssl::SslStream<S> {
        &mut self.inner
    }
}
impl<S> From<ssl::SslStream<S>> for SslStream<S> {
    fn from(ssl: ssl::SslStream<S>) -> Self {
        Self {
            inner: ssl
        }
    }
}

impl<S: Read + Write> Read for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S: Read + Write> Write for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncRead for SslStream<S> {
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        // Note that this does not forward to `S` because the buffer is
        // unconditionally filled in by OpenSSL, not the actual object `S`.
        // We're decrypting bytes from `S` into the buffer above!
        true
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncWrite for SslStream<S> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        match self.inner.shutdown() {
            Ok(ShutdownResult::Sent) |
            Ok(ShutdownResult::Received) => Ok(Async::Ready(())),
            Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => Ok(Async::Ready(())),
            Err(ref e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => Ok(Async::NotReady),
            Err(e) => Err(e.into_io_error().unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e))),
        }
    }
}

impl SslConnectorExt for SslConnector {
    fn connect_async<S>(&self, domain: &str, stream: S) -> ConnectAsync<S>
        where S: AsyncRead + AsyncWrite,
    {
        match self.configure() {
            Ok(s) => s.connect_async(domain, stream),
            Err(e) => ConnectAsync(ConnectAsyncInner::Error(HandshakeError::SetupFailure(e))),
        }
    }
}

impl ConnectConfigurationExt for ConnectConfiguration {
    fn connect_async<S>(self, domain: &str, stream: S) -> ConnectAsync<S>
        where S: AsyncRead + AsyncWrite,
    {
        ConnectAsync(ConnectAsyncInner::Start {
            config: self,
            domain: domain.to_string(),
            stream,
        })
    }
}

impl SslAcceptorExt for SslAcceptor {
    fn accept_async<S>(&self, stream: S) -> AcceptAsync<S>
        where S: AsyncRead + AsyncWrite,
    {
        AcceptAsync(AcceptAsyncInner::Start {
            acceptor: self.clone(),
            stream,
        })
    }
}

impl<S: Read + Write> Future for ConnectAsync<S> {
    type Item = SslStream<S>;
    type Error = HandshakeError<S>;

    fn poll(&mut self) -> Poll<SslStream<S>, HandshakeError<S>> {
        match mem::replace(&mut self.0, ConnectAsyncInner::Done) {
            ConnectAsyncInner::Start { config, domain, stream } => {
                match config.connect(&domain, stream) {
                    Ok(inner) => Ok(Async::Ready(SslStream { inner })),
                    Err(HandshakeError::WouldBlock(s)) => {
                        self.0 = ConnectAsyncInner::Handshake(s);
                        Ok(Async::NotReady)
                    }
                    Err(e) => Err(e),
                }
            }
            ConnectAsyncInner::Handshake(s) => match s.handshake() {
                Ok(inner) => Ok(Async::Ready(SslStream { inner })),
                Err(HandshakeError::WouldBlock(s)) => {
                    self.0 = ConnectAsyncInner::Handshake(s);
                    Ok(Async::NotReady)
                }
                Err(e) => Err(e),
            }
            ConnectAsyncInner::Error(e) => Err(e),
            ConnectAsyncInner::Done => panic!("future polled after completion")
        }
    }
}

impl<S: Read + Write> Future for AcceptAsync<S> {
    type Item = SslStream<S>;
    type Error = HandshakeError<S>;

    fn poll(&mut self) -> Poll<SslStream<S>, HandshakeError<S>> {
        match mem::replace(&mut self.0, AcceptAsyncInner::Done) {
            AcceptAsyncInner::Start { acceptor, stream } => {
                match acceptor.accept(stream) {
                    Ok(inner) => Ok(Async::Ready(SslStream { inner })),
                    Err(HandshakeError::WouldBlock(s)) => {
                        self.0 = AcceptAsyncInner::Handshake(s);
                        Ok(Async::NotReady)
                    }
                    Err(e) => Err(e),
                }
            }
            AcceptAsyncInner::Handshake(s) => match s.handshake() {
                Ok(inner) => Ok(Async::Ready(SslStream { inner })),
                Err(HandshakeError::WouldBlock(s)) => {
                    self.0 = AcceptAsyncInner::Handshake(s);
                    Ok(Async::NotReady)
                }
                Err(e) => Err(e),
            }
            AcceptAsyncInner::Done => panic!("future polled after completion")
        }
    }
}
