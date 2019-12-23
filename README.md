Building
========

ARM v7
------

On Ubuntu: from (https://github.com/japaric/rust-cross)
  0. Our target is an ARMv7 device, the triple for this target is `armv7-unknown-linux-gnueabihf`
  1. sudo apt-get install -qq gcc-arm-linux-gnueabihf
  2. rustup target add armv7-unknown-linux-gnueabihf
  3. cargo build --release --target=armv7-unknown-linux-gnueabihf


