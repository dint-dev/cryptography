[![Pub Package](https://img.shields.io/pub/v/cryptography.svg)](https://pub.dev/packages/cryptography)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Introduction
This package gives you a collection of cryptographic algorithms.

Some algorithms are implemented in pure Dart. Some algorithms are implemented with
[Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) and don't
work outside the browser yet.

Copyright 2019 Gohilla Ltd. Licensed under the [Apache License 2.0](LICENSE).

## Links
  * [Github repository](https://github.com/dint-dev/cryptography)
  * [Issue tracker](https://github.com/dint-dev/cryptography/issues)
  * [API reference](https://pub.dev/documentation/cryptography/latest/)
  * [Pub package](https://pub.dev/packages/cryptography)

## Available algorithms
### Key exchange algorithms
  * __P256/P384/P521__ _(currently browser-only)_
    * P256/P384/P521 are elliptic curves approved for key exchange by NIST.
  * __X25519__
    * X25519 is Elliptic Curve Diffie-Hellman (ECDH) using Curve25519. The algorithm is used in
      protocols such as SSH, TLS, Signal, WhatsApp, and Wireguard. Performance of this Dart
      implementation is about 1k exchanges per second on Macbook Pro.

### Digital signature algorithms
  * __P256/P384/P521__ _(currently browser-only)_
    * P256/P384/P521 are elliptic curves approved for digital signature by NIST.

### Ciphers
  * __AES (CBC, CTR, GCM)__ _(currently browser-only)_
    * AES is a symmetric cipher approved by NIST.
  * __CHACHA20__ and __AEAD_CHACHA20_POLY1305__
    * Chacha20 is a symmetric encryption algorithm that's simpler than AES and may also perform
      better than AES in CPUs that don't have AES instructions. The algorithm is used in protocols
      such as TLS, SSH, Signal, and Wireguard. Performance of this Dart implementation is about
      50-100MB/s on Macbook Pro.

### Message authentication codes
  * __HMAC__
    * The implementation uses [package:crypto](https://pub.dev/packages/crypto), a package by
      Dart SDK team.
  * __POLY1305__
    * Often used with Chacha20. The current implementation uses BigInt instead of optimized 128bit
      arithmetic, which is a known issue.

### Cryptographic hash functions
  * __BLAKE2S__
    * Blake2 is used in protocols such as WhatsApp and WireGuard.
  * __SHA1__
    * SHA1 is used by older software. The implementation uses [package:crypto](https://pub.dev/packages/crypto) (a package by Dart SDK team).
  * __SHA2__ (SHA224, SHA256, SHA384, SHA512)
    * SHA2 is approved by NIST. The implementation uses
      [package:crypto](https://pub.dev/packages/crypto) (a package by Dart SDK team).

# Getting started
## 1. Add dependency
```yaml
dependencies:
  cryptography: ^0.2.0
```

## 2. Use
### AEAD_CHACHA20_POLY1305
```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // Generate a random 256-bit secret key
  final secretKey = chacha20.newSecretKey();

  // Generate a random 96-bit nonce.
  final nonce = chacha20.newNonce();

  // Encrypt
  final result = await chacha20Poly1305Aead.encrypt(
    [1, 2, 3],
    secretKey: secretKey,
    nonce: nonce, // The same secretKey/nonce combination should not be used twice
    aad: const <int>[], // You can authenticate additional data here
  );
  print('Bytes: ${result.cipherText}');
  print('MAC: ${result.mac}');
}
```

### X25519
```dart
import 'package:cryptography/cryptography.dart';

void main() async {
  // Let's generate two keypairs.
  final localKeyPair = await x25519.newKeyPair();
  final remoteKeyPair = await x5519.newKeyPair();

  // We can now calculate a shared secret
  var sharedSecret = await x25519.sharedSecret(
    privateKey: localKeyPair.privateKey,
    publicKey: remoteKeyPair.publicKey,
  );
  print('Shared secret: ${sharedSecret.toHex()}');
}
```
