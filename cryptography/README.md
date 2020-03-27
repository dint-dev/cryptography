[![Pub Package](https://img.shields.io/pub/v/cryptography.svg)](https://pub.dev/packages/cryptography)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview
Popular cryptographic algorithms implemented in Dart.

We also recommend you to consider [package:kms](https://pub.dev/packages/kms), which enables you to
take advantage of hardware-based key managers as well as dedicated cloud services.

In browsers, the package takes advantage of [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
whenever possible, which should improve security and code size. Some algorithms are implemented
using [package:crypto](https://pub.dev/packages/crypto) (BSD-style license) or
[package:pointycastle](https://pub.dev/packages/pointycastle) (MPL 3.0 license).

Copyright 2019 Gohilla Ltd. Licensed under the [Apache License 2.0](LICENSE).

## Links
  * [Github repository](https://github.com/dint-dev/cryptography)
  * [Issue tracker](https://github.com/dint-dev/cryptography/issues)
  * [Pub package](https://pub.dev/packages/cryptography)
  * [API reference](https://pub.dev/documentation/cryptography/latest/)

## Available algorithms
### Key exchange algorithms
  * [ecdhP256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP256-constant.html) (ECDH P256/secp256r1)
    * In browsers, the implementation takes advantage of _Web Cryptography API_.
    * In other platforms, throws _UnsupportedError_.
  * [ecdhP384](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP384-constant.html) (ECDH P384/secp384r1)
    * In browsers, the implementation takes advantage of _Web Cryptography API_.
    * In other platforms, throws _UnsupportedError_.
  * [ecdhP521](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP521-constant.html) (ECDH P521/secp521r1)
    * In browsers, the implementation takes advantage of _Web Cryptography API_.
    * In other platforms, throws _UnsupportedError_.
  * [x25519](https://pub.dev/documentation/cryptography/latest/cryptography/x25519-constant.html) (A curve25519-based specification)
    * X25519 is used in protocols such as SSH, TLS, Signal, WhatsApp, and Wireguard. Performance of
      this Dart implementation is about 1k exchanges per second on Macbook Pro.

For more more documentation, see [KeyExchangeAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/KeyExchangeAlgorithm-class.html).

### Digital signature algorithms
  * [ecdsaP256Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP256Sha256-constant.html) (ECDSA P256/secp256r1 with SHA256)
    * In browsers, the implementation takes advantage of _Web Cryptography API_.
    * In other platforms, throws _UnsupportedError_.
  * [ecdsaP384Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP384Sha256-constant.html) (ECDSA P384/secp384r1 with SHA256)
    * In browsers, the implementation takes advantage of _Web Cryptography API_.
    * In other platforms, throws _UnsupportedError_.
  * [ecdsaP521Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP521Sha256-constant.html) (ECDSA P521/secp521r1 with SHA256)
    * In browsers, the implementation takes advantage of _Web Cryptography API_.
    * In other platforms, throws _UnsupportedError_.
  * [ed25519](https://pub.dev/documentation/cryptography/latest/cryptography/ed25519-constant.html)

For more more documentation, see [SignatureAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/SignatureAlgorithm-class.html).

### Ciphers
  * [aesCbc](https://pub.dev/documentation/cryptography/latest/cryptography/aesCbc-constant.html) (AES-CBC)
    * In browsers, the implementation takes advantage of _Web Cryptography API_.
    * In other platforms, the implementation uses _package:pointycastle_.
  * [aesCtr32](https://pub.dev/documentation/cryptography/latest/cryptography/aesCtr32-constant.html) (AES-CTR, 96-bit nonce, 32-bit counter)
    * In browsers, the implementation takes advantage of _Web Cryptography API_.
    * In other platforms, the implementation uses _package:pointycastle_.
  * [aesGcm](https://pub.dev/documentation/cryptography/latest/cryptography/aesGcm-constant.html) (AES-GCM)
    * In browsers, the implementation takes advantage of _Web Cryptography API_.
    * In other platforms, throws _UnsupportedError_.
  * [chacha20](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20-constant.html)
    * Chacha20 is a symmetric encryption algorithm that's simpler than AES and tends to perform
      better than the latter in CPUs that don't have AES instructions. The algorithm is used in
      protocols such as TLS, SSH, Signal, and Wireguard. Performance of this Dart implementation is
      about 50-100MB/s on Macbook Pro.
  * [chacha20Poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20Poly1305Aead-constant.html) (AEAD_CHACHA20_POLY1305)

For more more documentation, see [Cipher](https://pub.dev/documentation/cryptography/latest/cryptography/Cipher-class.html).

### Message authentication codes
  * [Hmac](https://pub.dev/documentation/cryptography/latest/cryptography/Hmac-class.html)
    * HMAC is a widely used message authentication code.
  * [poly1305](https://pub.dev/documentation/cryptography/latest/cryptography/poly1305-constant.html)
    * The current implementation uses BigInt instead of optimized 128bit arithmetic, which is a
      known issue.

For more more documentation, see [MacAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/MacAlgorithm-class.html).

### Cryptographic hash functions
  * [blake2s](https://pub.dev/documentation/cryptography/latest/cryptography/blake2s-constant.html) (BLAKE2S)
    * Blake2 is used in protocols such as WhatsApp and WireGuard.
  * [sha1](https://pub.dev/documentation/cryptography/latest/cryptography/sha1-constant.html) (SHA1)
    * The implementation uses _package:crypto_.
  * [sha224](https://pub.dev/documentation/cryptography/latest/cryptography/sha224-constant.html) (SHA2-224)
    * The implementation uses _package:crypto_.
  * [sha256](https://pub.dev/documentation/cryptography/latest/cryptography/sha256-constant.html) (SHA2-256)
    * The implementation uses _package:crypto_.
  * [sha384](https://pub.dev/documentation/cryptography/latest/cryptography/sha384-constant.html) (SHA2-384)
    * The implementation uses _package:crypto_.
  * [sha512](https://pub.dev/documentation/cryptography/latest/cryptography/sha512-constant.html) (SHA2-512)
    * The implementation uses _package:crypto_.
  * [sha3V224](https://pub.dev/documentation/cryptography/latest/cryptography/sha3V224-constant.html) (SHA3-224)
    * The implementation uses _package:pointycastle_.
  * [sha3V256](https://pub.dev/documentation/cryptography/latest/cryptography/sha3V256-constant.html) (SHA3-256)
    * The implementation uses _package:pointycastle_.
  * [sha3V384](https://pub.dev/documentation/cryptography/latest/cryptography/sha3V384-constant.html) (SHA3-384)
    * The implementation uses _package:pointycastle_.
  * [sha3V512](https://pub.dev/documentation/cryptography/latest/cryptography/sha3V512-constant.html) (SHA3-521)
    * The implementation uses _package:pointycastle_.

For more more documentation, see [HashAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/HashAlgorithm-class.html).


# Getting started
## 1. Add dependency
```yaml
dependencies:
  cryptography: ^0.2.5
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
