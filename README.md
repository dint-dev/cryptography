[![Pub Package](https://img.shields.io/pub/v/curve25519.svg)](https://pub.dev/packages/curve25519)
[![Build Status](https://travis-ci.org/gohilla/curve25519.svg?branch=master)](https://travis-ci.org/gohilla/curve25519)

# Introduction
A [Dart](https://dartlang.org) package that implements X25519 key exchange
([RFC 7748](https://tools.ietf.org/html/rfc7748)). X25519 is Elliptic Curve Diffie-Hellman
(ECDH) over Curve25519.

Supports all platforms, including browsers.

Authored by [terrier989](https://github.com/terrier989).
Licensed under the [Apache License 2.0](LICENSE).

## Contributing
  * [Github repository](https://github.com/terrier989/curve25519)

## Tests
  * We use:
    * Test vectors from the RFC.
    * An additional 10,000 rounds test vector.
  * Performance (on a recent Intel CPU) is about 1k operations per second.
