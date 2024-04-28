# chksum-hash-sha2-512

[![GitHub](https://img.shields.io/badge/github-chksum--rs%2Fhash--sha2--512-24292e?style=flat-square&logo=github "GitHub")](https://github.com/chksum-rs/hash-sha2-512)
[![Build](https://img.shields.io/github/actions/workflow/status/chksum-rs/hash-sha2-512/rust.yml?branch=master&style=flat-square&logo=github "Build")](https://github.com/chksum-rs/hash-sha2-512/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/chksum-hash-sha2-512?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-hash-sha2-512/)
[![MSRV](https://img.shields.io/badge/MSRV-1.63.0-informational?style=flat-square "MSRV")](https://github.com/chksum-rs/hash-sha2-512/blob/master/Cargo.toml)
[![deps.rs](https://deps.rs/crate/chksum-hash-sha2-512/0.0.1/status.svg?style=flat-square "deps.rs")](https://deps.rs/crate/chksum-hash-sha2-512/0.0.1)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/chksum-rs/hash-sha2-512?style=flat-square "LICENSE")](https://github.com/chksum-rs/hash-sha2-512/blob/master/LICENSE)

An implementation of SHA-2 512 hash algorithm for batch and stream computation.

## Setup

To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:

```toml
[dependencies]
chksum-hash-sha2-512 = "0.0.1"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-hash-sha2-512
```

## Usage

Use the `hash` function for batch digest calculation.

```rust
use chksum_hash_sha2_512 as sha2_512;

let digest = sha2_512::hash(b"example data");
assert_eq!(
    digest.to_hex_lowercase(),
    "ed59c5759a9ece516cec0c0623142d0e9fe70a27d750eee7fd38f4550d50addd873d0fa1a51fc823c1e3d5cada203f4a05d8325caacb7d3e0727a701f3f07e5f"
);
```

Use the `default` function to create a hash instance for stream digest calculation.

```rust
use chksum_hash_sha2_512 as sha2_512;

let digest = sha2_512::default()
    .update("example")
    .update(b"data")
    .update([0, 1, 2, 3])
    .digest();
assert_eq!(
    digest.to_hex_lowercase(),
    "57f35477757af6734892604de3846a97d2cc17cd37068373075e56a4843b3e9c83f9b435beae9fcf1da590e73e62fe20468f52ff13b095241fec77884086b090"
);
```

For more usage examples, refer to the documentation available at [docs.rs](https://docs.rs/chksum-hash-sha2-512/).

## License

This crate is licensed under the MIT License.
