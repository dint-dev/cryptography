[![Pub Package](https://img.shields.io/pub/v/cryptography.svg)](https://pub.dev/packages/cryptography)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview
This package gives you a collection of cryptographic algorithms.

Some algorithms are implemented in pure Dart and work in all platforms. Some algorithms are
implemented with [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
and work only in the browsers at the moment.

This package is used by [package:kms](https://pub.dev/packages/kms), which enables you to take
advantage of hardware-based key managers that are isolated from the main processor.

Copyright 2019 Gohilla Ltd. Licensed under the [Apache License 2.0](LICENSE).

## Links
  * [Github repository](https://github.com/dint-dev/cryptography)
  * [Issue tracker](https://github.com/dint-dev/cryptography/issues)
  * [Pub package](https://pub.dev/packages/cryptography)
  * [API reference](https://pub.dev/documentation/cryptography/latest/)

## Available algorithms
### Key exchange algorithms
  * [ecdhP256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP256-constant.html) (ECDH P256)
    * _Currently browser-only_
  * [ecdhP384](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP384-constant.html) (ECDH P384)
    * _Currently browser-only_
  * [ecdhP521](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP521-constant.html) (ECDH P521)
    * _Currently browser-only_
  * [x25519](https://pub.dev/documentation/cryptography/latest/cryptography/x25519-constant.html) (ECDH Curve25519)
    * X25519 is used in protocols such as SSH, TLS, Signal, WhatsApp, and Wireguard. Performance of
      this Dart implementation is about 1k exchanges per second on Macbook Pro.

For more more documentation, see [KeyExchangeAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/KeyExchangeAlgorithm-class.html).

### Digital signature algorithms
  * [ecdsaP256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP256-constant.html) (ECDSA P256)
    * _Currently browser-only_
  * [ecdsaP384](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP384-constant.html) (ECDSA P384)
    * _Currently browser-only_
  * [ecdsaP521](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP521-constant.html) (ECDSA P521)
    * _Currently browser-only_

For more more documentation, see [SignatureAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/SignatureAlgorithm-class.html).

### Ciphers
  * [aesCbc](https://pub.dev/documentation/cryptography/latest/cryptography/aesCbc-constant.html) (AES-CBC)
    * _Currently browser-only_
  * [aesCtr](https://pub.dev/documentation/cryptography/latest/cryptography/aesCtr-constant.html) (AES-CTR)
    * _Currently browser-only_
  * [aesGcm](https://pub.dev/documentation/cryptography/latest/cryptography/aesGcm-constant.html) (AES-GCM)
    * _Currently browser-only_
  * [chacha20](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20-constant.html)
    * Chacha20 is a symmetric encryption algorithm that's simpler than AES and tends to perform
      better than the latter in CPUs that don't have AES instructions. The algorithm is used in
      protocols such as TLS, SSH, Signal, and Wireguard. Performance of this Dart implementation is
      about 50-100MB/s on Macbook Pro.
  * [chacha20Poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20Poly1305Aead-constant.html) (AEAD_CHACHA20_POLY1305)

For more more documentation, see [Cipher](https://pub.dev/documentation/cryptography/latest/cryptography/Cipher-class.html).

### Message authentication codes
  * [Hmac](https://pub.dev/documentation/cryptography/latest/cryptography/Hmac-class.html)
    * HMAC-SHA256 is a widely used message authentication code.
  * [poly1305](https://pub.dev/documentation/cryptography/latest/cryptography/poly1305-constant.html)
    * Often used with Chacha20. The current implementation uses BigInt instead of optimized 128bit
      arithmetic, which is a known issue.

For more more documentation, see [MacAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/MacAlgorithm-class.html).

### Cryptographic hash functions
  * [blake2s](https://pub.dev/documentation/cryptography/latest/cryptography/blake2s-constant.html)
    * Blake2 is used in protocols such as WhatsApp and WireGuard.
  * [sha1](https://pub.dev/documentation/cryptography/latest/cryptography/sha1-constant.html)
    * Implemented with [package:crypto](https://pub.dev/packages/crypto).
  * [sha224](https://pub.dev/documentation/cryptography/latest/cryptography/sha224-constant.html)
    * Implemented with [package:crypto](https://pub.dev/packages/crypto).
  * [sha256](https://pub.dev/documentation/cryptography/latest/cryptography/sha256-constant.html)
    * Implemented with [package:crypto](https://pub.dev/packages/crypto).
  * [sha384](https://pub.dev/documentation/cryptography/latest/cryptography/sha384-constant.html)
    * Implemented with [package:crypto](https://pub.dev/packages/crypto).
  * [sha512](https://pub.dev/documentation/cryptography/latest/cryptography/sha512-constant.html)
    * Implemented with [package:crypto](https://pub.dev/packages/crypto).

For more more documentation, see [HashAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/HashAlgorithm-class.html).


# Getting started
## 1. Add dependency
```yaml
dependencies:
  cryptography: ^0.2.4
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

void main() async {
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
