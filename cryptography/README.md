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

## Used by
  * [kms](https://pub.dev/packages/kms)
    * A Dart package for hardware-based or cloud-based key management solutions.
  * _Add your project here?_

# Want to contribute?
  * Any help is appreciated! We recommend that you start by creating an issue in the
    [issue tracker](https://github.com/dint-dev/cryptography/issues).

## Some things to know
  * SHA1 and SHA2 implementations use [package:crypto](https://pub.dev/packages/crypto), which is
    maintained by Google. It's very limited so we decided to write this package.
  * We wrote pure Dart implementations for X25519, Chacha20 family, AES-CBC, AES-CTR, HKDF, HMAC,
    Poly1305, and Blake2s. We also added support for use of [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)
    (NIST elliptic curves, AES) in browsers.
  * The APIs generally include both _asynchronous_ and _synchronous_ methods (for instance,
    `sharedSecret(...)` and `sharedSecretSync(...)`). We recommend that you use asynchronous
    methods because they are able to take advantage of asynchronous platform APIs such as
    _Web Cryptography API_.

## Available algorithms
### Key exchange algorithms
  * NIST elliptic curves
    * [ecdhP256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP256-constant.html) (ECDH P256 / secp256r1)
    * [ecdhP384](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP384-constant.html) (ECDH P384 / secp384r1)
    * [ecdhP521](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP521-constant.html) (ECDH P521 / secp521r1)
    * Currently only supported in browsers (_Web Cryptography API_).
  * [x25519](https://pub.dev/documentation/cryptography/latest/cryptography/x25519-constant.html)
    * X25519 (curve25519-based Diffie-Hellman) is our recommendation for new applications. It's
      used in technologies such as SSH, TLS, Signal, WhatsApp, and Wireguard. Performance of our
      Dart implementation is about 1k exchanges per second on a Macbook Pro.

For more more documentation, see [KeyExchangeAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/KeyExchangeAlgorithm-class.html).

### Digital signature algorithms
  * NIST elliptic curves
    * [ecdsaP256Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP256Sha256-constant.html) (ECDSA P256 / secp256r1 with SHA256)
    * [ecdsaP384Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP384Sha256-constant.html) (ECDSA P384 / secp384r1 with SHA256)
    * [ecdsaP521Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP521Sha256-constant.html) (ECDSA P521 / secp521r1 with SHA256)
    * Currently only supported in browsers (_Web Cryptography API_).
  * [ed25519](https://pub.dev/documentation/cryptography/latest/cryptography/ed25519-constant.html)
    * ED25519 (curve25519-based EdDSA) is our recommendation for new applications. Performance of our
      Dart implementation is about 10 verifications per second. It has a lot low-hanging fruits for
      optimization.

For more more documentation, see [SignatureAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/SignatureAlgorithm-class.html).

### Symmetric encryption
  * NIST AES
    * [aesCbc](https://pub.dev/documentation/cryptography/latest/cryptography/aesCbc-constant.html) (AES-CBC)
    * [aesCtr](https://pub.dev/documentation/cryptography/latest/cryptography/aesCtr-constant.html) (AES-CTR)
    * [aesGcm](https://pub.dev/documentation/cryptography/latest/cryptography/aesGcm-constant.html) (AES-GCM)
      * Currently only supported in browsers (_Web Cryptography API_).
  * Chacha20 family
    * [chacha20](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20-constant.html)
    * [chacha20Poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20Poly1305Aead-constant.html) (AEAD_CHACHA20_POLY1305)
    * Chacha20 (AEAD) is our recommendation for new applications. It's used in technologies such as
      TLS, SSH, Signal, and Wireguard. Performance of our Dart implementation is about 50-100MB/s
      on a Macbook Pro.

For more more documentation, see [Cipher](https://pub.dev/documentation/cryptography/latest/cryptography/Cipher-class.html).

### Key derivation algorithms
  * [Hkdf](https://pub.dev/documentation/cryptography/latest/cryptography/Hkdf-class.html)

### Message authentication codes
  * [Hmac](https://pub.dev/documentation/cryptography/latest/cryptography/Hmac-class.html)
  * [poly1305](https://pub.dev/documentation/cryptography/latest/cryptography/poly1305-constant.html)

For more more documentation, see [MacAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/MacAlgorithm-class.html).

### Cryptographic hash functions
  * [blake2s](https://pub.dev/documentation/cryptography/latest/cryptography/blake2s-constant.html) (BLAKE2S)
  * [sha1](https://pub.dev/documentation/cryptography/latest/cryptography/sha1-constant.html) (SHA1)
  * [sha224](https://pub.dev/documentation/cryptography/latest/cryptography/sha224-constant.html) (SHA2-224)
  * [sha256](https://pub.dev/documentation/cryptography/latest/cryptography/sha256-constant.html) (SHA2-256)
  * [sha384](https://pub.dev/documentation/cryptography/latest/cryptography/sha384-constant.html) (SHA2-384)
  * [sha512](https://pub.dev/documentation/cryptography/latest/cryptography/sha512-constant.html) (SHA2-512)

For more more documentation, see [HashAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/HashAlgorithm-class.html).


# Adding dependency
In _pubspec.yaml_:
```yaml
dependencies:
  cryptography: ^0.3.2
```


# Examples
## Key agreement with X25519
In this example, we use [x25519](https://pub.dev/documentation/cryptography/latest/cryptography/x25519-constant.html).

```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // Let's generate two X25519 keypairs.
  final localKeyPair = await x25519.newKeyPair();
  final remoteKeyPair = await x5519.newKeyPair();

  // We can now calculate a shared secret
  final secretKey = await x25519.sharedSecret(
    localPrivateKey: localKeyPair.privateKey,
    remotePublicKey: remoteKeyPair.publicKey,
  );

  print('Shared secret: ${secretKey.bytes}');
}
```


## Digital signature with ED25519
In this example, we use [ed25519](https://pub.dev/documentation/cryptography/latest/cryptography/ed25519-constant.html).

```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // The bytes that we will sign
  final message = [1,2,3];

  // Generate a random ED25519 keypair
  final keyPair = await ed25519.newKeyPair();

  // Sign
  final signature = await ed25519.sign(
    message,
    keyPair: keyPair,
  );

  print('Signature: ${signature.bytes}');
  print('Public key: ${signature.publicKey.bytes}');

  // Verify signature
  final isVerified = await ed25519.verify(
    message,
    signature: signature,
  );

  print('Correct signature: $isVerified');
}
```


## Authenticated encryption with Chacha20 + Poly1305
In this example, we use [chacha20Poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20Poly1305Aead-constant.html).

```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // Choose the cipher
  final cipher = chacha20Poly1305Aead;

  // Choose some 256-bit secret key
  final secretKey = SecretKey.randomBytes(32);

  // Choose some unique (non-secret) 96-bit nonce.
  // The same (secretKey, nonce) combination should not be used twice!
  final nonce = Nonce.randomBytes(12);

  // Our message
  final message = <int>[1, 2, 3];

  // Encrypt
  final encrypted = await cipher.encrypt(
    message,
    secretKey: secretKey,
    nonce: nonce,
  );

  print('Encrypted: $encrypted');

  // Decrypt
  final decrypted = await cipher.decrypt(
    encrypted,
    secretKey: secretKey,
    nonce: nonce,
  );

  print('Decrypted: $decrypted');
}
```


## Authenticated encryption with AES-CTR + HMAC-SHA256
In this example, we use [aesCtr](https://pub.dev/documentation/cryptography/latest/cryptography/aesCtr-constant.html)
and [Hmac](https://pub.dev/documentation/cryptography/latest/cryptography/Hmac-class.html).

```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // Choose the cipher
  final cipher = CipherWithAppendedMac(aesCtr, Hmac(sha256));

  // Choose some 256-bit secret key
  final secretKey = SecretKey.randomBytes(16);

  // Choose some unique (non-secret) nonce (max 16 bytes).
  // The same (secretKey, nonce) combination should not be used twice!
  final nonce = Nonce.randomBytes(12);

  // Our message
  final message = <int>[1, 2, 3];

  // Encrypt
  final encrypted = await cipher.encrypt(
    message,
    secretKey: secretKey,
    nonce: nonce,
  );

  print('Encrypted: $encrypted');

  // Decrypt
  final decrypted = await cipher.decrypt(
    encrypted,
    secretKey: secretKey,
    nonce: nonce,
  );

  print('Decrypted: $decrypted');
}
```


## Message authentication with HMAC-BLAKE2S
In this example, we use [Hmac](https://pub.dev/documentation/cryptography/latest/cryptography/Hmac-class.html)
and [blake2s](https://pub.dev/documentation/cryptography/latest/cryptography/blake2s-constant.html).

```dart
import 'package:cryptography/cryptography.dart';
import 'dart:convert';

Future<void> main() {
  // Choose a secret key
  final secretKey = SecretKey(utf8.encode('qwerty'));

  // Create a HMAC-BLAKE2S sink
  final macAlgorithm = const Hmac(blake2s);
  final sink = macAlgorithm.newSink(secretKey: secretKey);

  // Add all parts of the authenticated message
  sink.add([1,2]);
  sink.add([3]);

  // Calculate MAC
  sink.close();
  final macBytes = sink.mac.bytes;

  print('Message authentication code: $macBytes');
}
```