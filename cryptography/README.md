[![Pub Package](https://img.shields.io/pub/v/cryptography.svg)](https://pub.dev/packages/cryptography)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview
Popular cryptographic algorithms for [Dart](https://dart.dev) / [Flutter](https://flutter.dev)
developers.

Maintained by Gohilla Ltd. Licensed under the [Apache License 2.0](LICENSE).

This package is:
  * __Easy to use__. The API is easy to understand and encourages good defaults.
  * __Multi-platform__. It's easy to customize implementation of X in platform Y.
  * __Fast.__ By default, we use platform APIs when available. For example, SHA-512 is over 100
    times faster than _package:crypto_ in browsers.

Any feedback, issue reports, or pull requests are appreciated!

## Links
  * [Github project](https://github.com/dint-dev/cryptography)
  * [Issue tracker](https://github.com/dint-dev/cryptography/issues)
  * [Pub package](https://pub.dev/packages/cryptography)
  * [API reference](https://pub.dev/documentation/cryptography/latest/)

## Some packages that depend on this
  * [cryptography_flutter](https://pub.dev/packages/cryptography_flutter).
    * Android / iOS cryptography support.
  * [jwk](https://pub.dev/packages/jwk)
    * JWK (JSON Web Key) support.

# Key concepts
## Key classes
The usual arguments to algorithms are:
  * [SecretKeyData](https://pub.dev/documentation/cryptography/latest/cryptography/SecretKeyData-class.html)
    is used by ciphers, message authentication codes, and key derivation functions.
  * [KeyPair](https://pub.dev/documentation/cryptography/latest/cryptography/KeyPair-class.html) and
    [PublicKey](https://pub.dev/documentation/cryptography/latest/cryptography/PublicKey-class.html)
    are used by key exchange and signature algorithms.
      * [SimpleKeyPairData](https://pub.dev/documentation/cryptography/latest/cryptography/SimpleKeyPairData-class.html)
        and [SimplePublicKey](https://pub.dev/documentation/cryptography/latest/cryptography/SimplePublicKey-class.html)
        are used when keys are simple byte sequences.
      * [EcKeyPairData](https://pub.dev/documentation/cryptography/latest/cryptography/EcKeyPairData-class.html)
        and [EcPublicKey](https://pub.dev/documentation/cryptography/latest/cryptography/EcPublicKey-class.html)
        are used by P-256 / P-384 / P-512 algorithms.
      * [RsaKeyPairData](https://pub.dev/documentation/cryptography/latest/cryptography/RsaKeyPairData-class.html)
        and [RsaPublicKey](https://pub.dev/documentation/cryptography/latest/cryptography/RsaPublicKey-class.html)
        are used by RSA algorithms.
      * For encoding/decoding private/public keys in JWK (JSON Web Key) format, use
        [package:jwk](https://pub.dev/packages/jwk).
      * For encoding/decoding X.509, PKCS12, and other formats, we don't have recommended packages
        at the moment.

## Algorithms by type
### Ciphers
The following [Cipher](https://pub.dev/documentation/cryptography/latest/cryptography/Cipher-class.html)
implementations are available:
  * AES
    * [AesCbc](https://pub.dev/documentation/cryptography/latest/cryptography/AesCbc-class.html) (AES-CBC)
    * [AesCtr](https://pub.dev/documentation/cryptography/latest/cryptography/AesCtr-class.html) (AES-CTR)
    * [AesGcm](https://pub.dev/documentation/cryptography/latest/cryptography/AesGcm-class.html) (AES-GCM)
    * Throughputs of the pure Dart implementations are about 50 MB/s, AES-GCM about 5-10 MB/s.
    * Throughputs of the [BrowserCryptography](https://pub.dev/documentation/cryptography/latest/browser/BrowserCryptography-class.html)
      implementations are about 400 - 700 MB/s.
  * ChaCha20 / XChaCha20
    * [Chacha20](https://pub.dev/documentation/cryptography/latest/cryptography/Chacha20-class.html)
    * [Chacha20.poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/Chacha20/poly1305Aead.html) (AEAD_CHACHA20_POLY1305)
    * [Xchacha20](https://pub.dev/documentation/cryptography/latest/cryptography/Xchacha20-class.html)
    * [Xchacha20.poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/Xchacha20/poly1305Aead.html) (AEAD_XCHACHA20_POLY1305)
    * Throughput of the pure Dart implementation is 40 - 140 MB/s in VM.

### Digital signature algorithms
The following [SignatureAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/SignatureAlgorithm-class.html)
implementations are available:
  * [Ed25519](https://pub.dev/documentation/cryptography/latest/cryptography/Ed25519-class.html) (curve25519 EdDSA)
    * Performance of the pure Dart implementation is around 200 (signatures or verifications) per second
      in VM and about 50 in browsers.
  * Elliptic curves approved by NIST
    * [Ecdsa.p256](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdsa/p256.html) (ECDSA P256 / secp256r1 / prime256v1 + SHA256)
    * [Ecdsa.p384](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdsa/p384.html) (ECDSA P384 / secp384r1 / prime384v1 + SHA384)
    * [Ecdsa.p521](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdsa/p521.html) (ECDSA P521 / secp521r1 / prime521v1 + SHA256)
    * We don't have implementations of these in pure Dart.
  * RSA
    * [RsaPss](https://pub.dev/documentation/cryptography/latest/cryptography/RsaPss-class.html) (RSA-PSS)
    * [RsaSsaPkcs1v15](https://pub.dev/documentation/cryptography/latest/cryptography/RsaSsaPkcs1v15-class.html) (RSASSA-PKCS1v15)
    * We don't have implementations of these in pure Dart.

### Key exchange algorithms
The following [KeyExchangeAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/KeyExchangeAlgorithm-class.html)
implementations are available:
  * Elliptic curves approved by NIST
    * [Ecdh.p256](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdh/p256.html) (ECDH P256 / secp256r1 / prime256v1)
    * [Ecdh.p384](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdh/p384.html) (ECDH P384 / secp384r1 / prime384v1)
    * [Ecdh.p521](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdh/p521.html) (ECDH P521 / secp521r1 / prime521v1)
    * We don't have implementations of these in pure Dart.
  * [X25519](https://pub.dev/documentation/cryptography/latest/cryptography/X25519-class.html) (curve25519 Diffie-Hellman)
    * Throughput of the pure Dart implementation is around 1000 key agreements per second (in VM).

### Key derivation algorithms
The following implementations are available:
  * [Hchacha20](https://pub.dev/documentation/cryptography/latest/cryptography/Hchacha20-clas.html)
  * [Hkdf](https://pub.dev/documentation/cryptography/latest/cryptography/Hkdf-class.html) (HKDF)
  * [Pbkdf2](https://pub.dev/documentation/cryptography/latest/cryptography/Pbkdf2-class.html) (PBKDF2)

### Message authentication codes
The following [MacAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/MacAlgorithm-class.html)
implementations are available:
  * [Hmac](https://pub.dev/documentation/cryptography/latest/cryptography/Hmac-class.html)
  * [Poly1305](https://pub.dev/documentation/cryptography/latest/cryptography/Poly1305-class.html)

### Cryptographic hash functions
The following [HashAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/HashAlgorithm-class.html)
implementations are available:
  * [Blake2b](https://pub.dev/documentation/cryptography/latest/cryptography/Blake2b-class.html) (BLAKE2B)
  * [Blake2s](https://pub.dev/documentation/cryptography/latest/cryptography/Blake2s-class.html) (BLAKE2S)
  * [Sha1](https://pub.dev/documentation/cryptography/latest/cryptography/Sha1-class.html) (SHA1)
  * [Sha224](https://pub.dev/documentation/cryptography/latest/cryptography/Sha224-class.html) (SHA2-224)
  * [Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/Sha256-class.html) (SHA2-256)
  * [Sha384](https://pub.dev/documentation/cryptography/latest/cryptography/Sha384-class.html) (SHA2-384)
  * [Sha512](https://pub.dev/documentation/cryptography/latest/cryptography/Sha512-class.html) (SHA2-512)

## Available implementations
The abstract class [Cryptography](https://pub.dev/documentation/cryptography/latest/cryptography/Cryptography-class.html)
has factory methods that return implementations of cryptographic algorithms. The default
implementation is _BrowserCryptography_ (which works in all platforms, not just browser). You can
write your own _Cryptography_ subclass if you need to.

We wrote the following three implementations of `Cryptography`:
  * [DartCryptography](https://pub.dev/documentation/cryptography/latest/cryptography.dart/DartCryptography-class.html)
    * Gives you implementations written in pure Dart implementations. They work in all platforms.
    * SHA1 / SHA2 uses implementation in [package:crypto](https://pub.dev/packages/crypto), which
      is maintained by Google. The rest of the algorithms in _DartCryptography_ are written and tested by us.
    * _DartCryptography_ gives:
      * AesCbc
      * AesCtr
      * AesGcm
      * Blake2b
      * Blake2s
      * Chacha20
      * Chacha20.poly1305Aead
      * Ed25519
      * Hkdf
      * Hmac
      * Pbkdf2
      * Poly1305
      * Sha1
      * Sha224
      * Sha256
      * Sha384
      * Sha512
      * X25519
      * Xchacha20
      * Xchacha20.poly1305Aead
  * [BrowserCryptography](https://pub.dev/documentation/cryptography/latest/cryptography.browser/BrowserCryptography-class.html)
    * Extends _DartCryptography_.
    * Uses [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/) (_crypto.subtle_).the
    * In browsers, _BrowserCryptography_ gives:
      * AesCbc
      * AesCtr
      * AesGcm
      * Ecdh.p256
      * Ecdh.p384
      * Ecdh.p512
      * Ecdsa.p256
      * Ecdsa.p384
      * Ecdsa.p512
      * Hkdf
      * Hmac
      * Pbkdf2
      * RsaPss
      * RsaSsaPkcs1v15
      * Sha1
      * Sha256
      * Sha384
      * Sha512
  * [FlutterCryptography](https://pub.dev/documentation/cryptography_flutter/latest/cryptography/FlutterCryptography-class.html)
    * A Flutter plugin available in [cryptography_flutter](https://pub.dev/packages/cryptography_flutter).
    * Extends _BrowserCryptography_.
    * Enabled with [FlutterCryptography.enable()](https://pub.dev/documentation/cryptography_flutter/latest/cryptography/FlutterCryptography/enable.html).
    * In Android, _FlutterCryptography_ gives:
      * AesCbc
      * AesCtr
      * AesGcm
      * Chacha20
      * Chacha20.poly1305Aead
    * In iOS, _FlutterCryptography_ gives:
      * AesGcm
      * Chacha20
      * Chacha20.poly1305Aead

# Getting started
In _pubspec.yaml_:
```yaml
dependencies:
  cryptography: ^2.0.2
```

If you use Flutter, we recommend that you also add [cryptography_flutter](https://pub.dev/packages/cryptography_flutter):
```yaml
dependencies:
  cryptography: ^2.0.2
  cryptography_flutter: ^2.0.1
```

# Examples
## Digital signature
In this example, we use [Ed25519](https://pub.dev/documentation/cryptography/latest/cryptography/Ed25519-class.html).

```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // The message that we will sign
  final message = <int>[1,2,3];

  // Generate a keypair.
  final algorithm = Ed25519();
  final keyPair = await algorithm.newKeyPair();

  // Sign
  final signature = await algorithm.sign(
    message,
    keyPair: keyPair,
  );
  print('Signature: ${signature.bytes}');
  print('Public key: ${signature.publicKey.bytes}');

  // Verify signature
  final isSignatureCorrect = await algorithm.verify(
    message,
    signature: signature,
  );
  print('Correct signature: $isSignatureCorrect');
}
```

## Key agreement
In this example, we use [X25519](https://pub.dev/documentation/cryptography/latest/cryptography/X25519-class.html).

```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  final algorithm = X25519();

  // Alice chooses her key pair
  final aliceKeyPair = await algorithm.newKeyPair();

  // Alice knows Bob's public key
  final bobKeyPair = await algorithm.newKeyPair();
  final bobPublicKey = await bobKeyPair.extractPublicKey();

  // Alice calculates the shared secret.
  final sharedSecret = await algorithm.sharedSecretKey(
    keyPair: aliceKeyPair,
    remotePublicKey: bobPublicKey,
  );
  final sharedSecretBytes = await aliceKeyPair.extractBytes();
  print('Shared secret: $sharedSecretBytes');
}
```

## Authenticated encryption
In this example, we encrypt a message with [AesCtr](https://pub.dev/documentation/cryptography/latest/cryptography/AesCtr-class.html)
and append a [Hmac](https://pub.dev/documentation/cryptography/latest/cryptography/Hmac-class.html)
message authentication code.

```dart
import 'dart:convert';
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // Message we want to encrypt
  final message = utf8.encode('Hello encryption!');

  // Choose the cipher
  final algorithm = AesCtr(macAlgorithm: Hmac.sha256()));

  // Generate a random secret key.
  final secretKey = algorithm.newSecretKey();
  final secretKeyBytes = await secretKey.extractBytes();
  print('Secret key: ${secretKeyBytes}');

  // Encrypt
  final secretBox = await algorithm.encrypt(
    message,
    secretKey: secretKey,
  );
  print('Nonce: ${secretBox.nonce}');
  print('Ciphertext: ${secretBox.cipherText}');
  print('MAC: ${secretBox.mac.bytes}');

  // Decrypt
  final clearText = await algorithm.decrypt(
    secretBox,
    secretKey: secretKey,
  );
  print('Cleartext: ${utf8.decode(clearText)}');
}
```

## Hashing
In this example, we use [Sha512](https://pub.dev/documentation/cryptography/latest/cryptography/Sha512-class.html).

```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  final sink = Sha512().newHashSink();

  // Add all parts of the authenticated message
  sink.add([1,2,3]);
  sink.add([4,5]);

  // Calculate hash
  sink.close();
  final hash = await sink.hash();

  print('SHA-512 hash: ${hash.bytes}');
}
```