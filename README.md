# brainwallet
Rust command line program for Bitcoin brainwallet as implemented at https://www.bitaddress.org.

To run it, first install Rust, e.g. from https://rustup.rs.

Then you can build it with `cargo build --release`. Then you can run it like this:
```
./target/release/brainwallet compressed 123456789012345
Bitcoin Address: 1FCGr3TqJ59vjRsZtSLvaTSANeGz81gc7Y
Private Key (Wallet Import Format): L4oxMgPbBytmiTZz5mRFghQ3E6ixzUiAbP4gZeKXWadKhXyLGoVw
```
