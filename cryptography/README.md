[![Pub Package](https://img.shields.io/pub/v/cryptography.svg)](https://pub.dev/packages/cryptography)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview
Popular cryptographic algorithms implemented in Dart.

Copyright 2020 Gohilla Ltd. Licensed under the [Apache License 2.0](LICENSE).

## Links
  * [Github repository](https://github.com/dint-dev/cryptography)
  * [Issue tracker](https://github.com/dint-dev/cryptography/issues)
  * [Pub package](https://pub.dev/packages/cryptography)
  * [API reference](https://pub.dev/documentation/cryptography/latest/)

## Some things to know
  * SHA1 and SHA2 implementations use [package:crypto](https://pub.dev/packages/crypto).
    It's maintained by Google, but unfortunately didn't cover some algorithms we needed.
  * We wrote pure Dart implementations for X25519, Chacha20 family, HKDF, HMAC, Poly1305, and
    Blake2S.
  * We wrote support for automatic use of [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)
    (NIST elliptic curves, AES) in browsers.
  * AES in non-browsers is implemented with [package:pointycastle](https://pub.dev/packages/pointycastle),
    an MPL 3.0 licensed package derived from Bouncy Castle. We may eliminate the dependency at some
    point.
  * The APIs generally include both _asynchronous_ and _synchronous_ methods (for instance,
    `sharedSecret(...)` and `sharedSecretSync(...)`). We recommend that you use asynchronous
    methods because they are able to take advantage of asynchronous platform APIs such as
    _Web Cryptography API_.

## Used by
  * [kms](https://pub.dev/packages/kms)
    * A Dart package for hardware-based or cloud-based key management solutions.
  * _Add your project here?_

# Want to contribute?
  * We recommend that you start by creating an issue in the
    [issue tracker](https://github.com/dint-dev/cryptography/issues).

## Available algorithms
### Key exchange algorithms
  * NIST curves
    * [ecdhP256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP256-constant.html) (ECDH P256 / secp256r1)
    * [ecdhP384](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP384-constant.html) (ECDH P384 / secp384r1)
    * [ecdhP521](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP521-constant.html) (ECDH P521 / secp521r1)
    * Currently only supported in browsers (_Web Cryptography API_).
  * [x25519](https://pub.dev/documentation/cryptography/latest/cryptography/x25519-constant.html)
    * X25519 (curve25519-based Diffie-Hellman) has been adopted by technologies such as SSH, TLS,
      Signal, WhatsApp, and Wireguard. Performance of our Dart implementation is about 1k exchanges
      per second on a Macbook Pro.

For more more documentation, see [KeyExchangeAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/KeyExchangeAlgorithm-class.html).

### Digital signature algorithms
  * NIST curves
    * [ecdsaP256Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP256Sha256-constant.html) (ECDSA P256 / secp256r1 with SHA256)
    * [ecdsaP384Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP384Sha256-constant.html) (ECDSA P384 / secp384r1 with SHA256)
    * [ecdsaP521Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP521Sha256-constant.html) (ECDSA P521 / secp521r1 with SHA256)
    * Currently only supported in browsers (_Web Cryptography API_).
  * [ed25519](https://pub.dev/documentation/cryptography/latest/cryptography/ed25519-constant.html)

For more more documentation, see [SignatureAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/SignatureAlgorithm-class.html).

### Ciphers
  * AES
    * [aesCbc](https://pub.dev/documentation/cryptography/latest/cryptography/aesCbc-constant.html) (AES-CBC)
    * [aesCtr32](https://pub.dev/documentation/cryptography/latest/cryptography/aesCtr32-constant.html) (AES-CTR, 96-bit nonce, 32-bit counter)
    * [aesGcm](https://pub.dev/documentation/cryptography/latest/cryptography/aesGcm-constant.html) (AES-GCM)
      * Currently only supported in browsers (_Web Cryptography API_).
  * Chacha20 family
    * [chacha20](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20-constant.html)
    * [chacha20Poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20Poly1305Aead-constant.html) (AEAD_CHACHA20_POLY1305)
    * Chacha20 is a symmetric encryption algorithm that's simpler than AES and tends to perform
      better than the latter in CPUs that don't have AES instructions. The algorithm has been
      adopted by technologies such as TLS, SSH, Signal, and Wireguard. Performance of our Dart
      implementation is about 50-100MB/s on Macbook Pro.

For more more documentation, see [Cipher](https://pub.dev/documentation/cryptography/latest/cryptography/Cipher-class.html).

### Key derivation algorithms
  * [Hkdf](https://pub.dev/documentation/cryptography/latest/cryptography/Hkdf-class.html)

### Message authentication codes
  * [Hmac](https://pub.dev/documentation/cryptography/latest/cryptography/Hmac-class.html)
  * [poly1305](https://pub.dev/documentation/cryptography/latest/cryptography/poly1305-constant.html)
    * The current implementation uses BigInt instead of optimized 128bit arithmetic, which is a
      known issue.

For more more documentation, see [MacAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/MacAlgorithm-class.html).

### Cryptographic hash functions
  * [blake2s](https://pub.dev/documentation/cryptography/latest/cryptography/blake2s-constant.html) (BLAKE2S)
  * [sha1](https://pub.dev/documentation/cryptography/latest/cryptography/sha1-constant.html) (SHA1)
  * [sha224](https://pub.dev/documentation/cryptography/latest/cryptography/sha224-constant.html) (SHA2-224)
  * [sha256](https://pub.dev/documentation/cryptography/latest/cryptography/sha256-constant.html) (SHA2-256)
  * [sha384](https://pub.dev/documentation/cryptography/latest/cryptography/sha384-constant.html) (SHA2-384)
  * [sha512](https://pub.dev/documentation/cryptography/latest/cryptography/sha512-constant.html) (SHA2-512)

For more more documentation, see [HashAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/HashAlgorithm-class.html).


# Getting started
## 1. Add dependency
```yaml
dependencies:
  cryptography: ^0.3.0
```

## 2. Use
### Encryption
In this example, we use [chacha20](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20Poly1305Aead-constant.html).
```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // Generate a random 256-bit secret key
  final secretKey = await chacha20.newSecretKey();

  // Generate a random 96-bit nonce.
  final nonce = chacha20.newNonce();

  // Encrypt
  final result = await chacha20Poly1305Aead.encrypt(
    [1, 2, 3],
    secretKey: secretKey,
    nonce: nonce, // The same secretKey/nonce combination should not be used twice
    aad: const <int>[], // You can include additional non-encrypted data here
  );
  print('Ciphertext: ${result.cipherText}');
  print('MAC: ${result.mac}');
}
```

### Key exchange
In this example, we use [x25519](https://pub.dev/documentation/cryptography/latest/cryptography/x25519-constant.html).
```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // Let's generate two keypairs.
  final localKeyPair = await x25519.newKeyPair();
  final remoteKeyPair = await x5519.newKeyPair();

  // We can now calculate a shared secret
  var secretKey = await x25519.sharedSecret(
    localPrivateKey: localKeyPair.privateKey,
    remotePublicKey: remoteKeyPair.publicKey,
  );
}
```
