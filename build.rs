#![allow(clippy::unusual_byte_groupings)]
use std::env;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ossl111)");

    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();

        if version >= 0x1_01_01_00_0 {
            println!("cargo:rustc-cfg=ossl111");
        }
    }
}
