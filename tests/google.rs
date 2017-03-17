extern crate futures;
extern crate openssl;
extern crate tokio_core;
extern crate tokio_openssl;
extern crate tokio_io;

use std::io;
use std::net::ToSocketAddrs;

use futures::Future;
use openssl::ssl::{SslConnectorBuilder, SslMethod};
use tokio_io::io::{flush, write_all, read_to_end};
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
use tokio_openssl::SslConnectorExt;

macro_rules! t {
    ($e:expr) => (match $e {
        Ok(e) => e,
        Err(e) => panic!("{} failed with {:?}", stringify!($e), e),
    })
}

fn openssl2io(e: openssl::ssl::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

#[test]
fn fetch_google() {
    let addr = t!("google.com:443".to_socket_addrs()).next().unwrap();

    let mut l = t!(Core::new());
    let client = TcpStream::connect(&addr, &l.handle());


    // Send off the request by first negotiating an SSL handshake, then writing
    // of our request, then flushing, then finally read off the response.
    let data = client.and_then(move |socket| {
        let builder = t!(SslConnectorBuilder::new(SslMethod::tls()));
        let connector = builder.build();
        connector.connect_async("google.com", socket).map_err(openssl2io)
    }).and_then(|socket| {
        write_all(socket, b"GET / HTTP/1.0\r\n\r\n")
    }).and_then(|(socket, _)| {
        flush(socket)
    }).and_then(|socket| {
        read_to_end(socket, Vec::new())
    });

    let (_, data) = t!(l.run(data));

    // any response code is fine
    assert!(data.starts_with(b"HTTP/1.0 "));

    let data = String::from_utf8_lossy(&data);
    let data = data.trim_right();
    assert!(data.ends_with("</html>") || data.ends_with("</HTML>"));
}
