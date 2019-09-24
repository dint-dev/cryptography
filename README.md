[![Pub Package](https://img.shields.io/pub/v/cryptography.svg)](https://pub.dev/packages/cryptography)
[![Build Status](https://travis-ci.org/gohilla/curve25519.svg?branch=master)](https://travis-ci.org/gohilla/curve25519)

# Introduction
A collection of cryptographic algorithms implemented in Dart.

The package is licensed under the [Apache License 2.0](LICENSE). Two previously separate packages,
[chacha20](https://pub.dev/packages/chacha20) and [curve25519](https://pub.dev/packages/curve25519),
have been merged into this package.

## Contributing
  * [Github repository](https://github.com/gohilla/cryptography.dart)

## Algorithms
### Elliptic curve cryptography
  * X25519 (Curve25519)
  * _(Additional algorithms are welcomed)_

### Ciphers
  * Chacha20
  * _(Additional algorithms are welcomed)_

### Hashes
  * SHA2 (224/256/384/512)
    * The implementation uses [package:crypto](https://pub.dev/packages/crypto)
  * _(Additional algorithms are welcomed)_

### Other
  * HMAC

# Details
## Chacha20
Tests use examples from [RFC 7539](https://tools.ietf.org/html/rfc7539), an implementation guide by
the the Internet Research Task Force.

Performance on new Apple laptops is about 50-100MB/s. Optimized C implementations can be up to a
magnitude faster.

An example:
```dart
import 'package:cryptography/cryptography.dart';

void main() {
  // Generate a random 256-bit secret key
  final secretKey = chacha20.newSecretKey();

  // Generate a random 96-bit nonce.
  final nonce = chacha20.newNonce();

  // Encrypt
  final result = chacha20.encrypt(
    [1, 2, 3],
    secretKey,
    nonce: nonce,
  );
  print(result);
}
```

## X25519
X25519 is Elliptic Curve Diffie-Hellman (ECDH) over Curve25519. Tests use test vectors from X25519
key exchange specification ([RFC 7748](https://tools.ietf.org/html/rfc7748)) and an additional
10,000 round test vector.

Performance on new Apple laptops is about 1k operations per second. Optimized C implementations can
be up to a magnitude faster.