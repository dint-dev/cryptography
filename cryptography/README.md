[![Pub Package](https://img.shields.io/pub/v/cryptography.svg)](https://pub.dev/packages/cryptography)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview
Popular cryptographic algorithms for [Dart](https://dart.dev) / [Flutter](https://flutter.dev)
developers. Copyright 2019-2020 Gohilla Ltd. Licensed under the [Apache License 2.0](LICENSE).

This package is:
  * __Safe__. Plenty of tests. No license risks. Used in commercial products.
  * __Fast.__ For example, SHA-512 in browsers can be 100 times faster than _package:crypto_.

Any feedback, issue reports, or pull requests are appreciated!

See [our Github repository](https://github.com/dint-dev/cryptography).

## Links
  * [Github project](https://github.com/dint-dev/cryptography)
  * [Issue tracker](https://github.com/dint-dev/cryptography/issues)
  * [Pub package](https://pub.dev/packages/cryptography)
  * [API reference](https://pub.dev/documentation/cryptography/latest/)

## Used by
  * [kms](https://pub.dev/packages/kms)
    * A Dart package for hardware-based or cloud-based key management solutions.
  * [kms_flutter](https://pub.dev/packages/kms_flutter)
    * Uses native APIs for storing cryptographic keys in Android and iOS.
  * [noise_protocol](https://pub.dev/packages/noise_protocol)
    * An implementation of Noise handshake protocol.
  * _Add your project here?_

## Some things to know
  * SHA1 and SHA2 implementations use the package [crypto](https://pub.dev/packages/crypto), which
    is maintained by Google and contains only hash functions and HMAC.
  * We wrote pure Dart implementations for X25519, ED25519, RSA-PSS, ChaCha20 / XChacha20, AES-CBC,
    AES-CTR, AES-GCM, HKDF, HMAC, Poly1305, and BLAKE2S.
  * We implemented automatic use of [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)
    (_crypto.subtle_) when you use SHA1, SHA2, AES, ECDH, ECDSA, or RSA in browsers.
  * The APIs generally include both _asynchronous_ and _synchronous_ methods.  Only the
    asynchronous methods are able to use Web Crypto APIs. For instance, you can calculate a SHA-512
    hash with `sha512.hash(bytes)` or `sha512.hashSync(bytes)`. In browsers, asynchronous version
    can be as much as 100 times faster. In other platforms the synchronous version is slightly
    faster. We recommend that developers use asynchronous methods.
  * If Dart SDK decides to expose _BoringSSL_ functions ([SDK issue](https://github.com/dart-lang/sdk/issues/34659)),
    we will use them as much as possible.

## Cryptographic material classes
  * [SecretKey](https://pub.dev/documentation/cryptography/latest/cryptography/SecretKey-class.html)
    is used by symmetric cryptography.
  * [KeyPair](https://pub.dev/documentation/cryptography/latest/cryptography/KeyPair-class.html)
    ([PrivateKey](https://pub.dev/documentation/cryptography/latest/cryptography/PrivateKey-class.html)
    and [PublicKey](https://pub.dev/documentation/cryptography/latest/cryptography/PublicKey-class.html))
    is used by asymmetric cryptography.
    * Many data formats exist for storing RSA and elliptic curve keys. This package contains
      JSON Web Key (JWK) implementations [JwkPrivateKey](https://pub.dev/documentation/cryptography/latest/cryptography/JwkPrivateKey-class.html)
      and [JwkPublicKey](https://pub.dev/documentation/cryptography/latest/cryptography/JwkPublicKey-class.html).
  * [Nonce](https://pub.dev/documentation/cryptography/latest/cryptography/Nonce-class.html)
    ("initialization vector", "IV", or "salt") is some non-secret, unique value required by many
    functions.

## Available algorithms
### Key exchange algorithms
The following [KeyExchangeAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/KeyExchangeAlgorithm-class.html) implementations are available:
  * Elliptic curves approved by NIST ([read about the algorithm](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography))
    * [ecdhP256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP256-constant.html) (ECDH P256 / secp256r1 / prime256v1)
    * [ecdhP384](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP384-constant.html) (ECDH P384 / secp384r1 / prime384v1)
    * [ecdhP521](https://pub.dev/documentation/cryptography/latest/cryptography/ecdhP521-constant.html) (ECDH P521 / secp521r1 / prime521v1)
    * Currently implemented only in browsers.
  * [x25519](https://pub.dev/documentation/cryptography/latest/cryptography/x25519-constant.html) (curve25519 Diffie-Hellman)
    * In our benchmarks, the performance is around 1k operations per second in VM.

For more more documentation, see [KeyExchangeAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/KeyExchangeAlgorithm-class.html).

### Digital signature algorithms
The following [SignatureAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/SignatureAlgorithm-class.html) implementations are available:
  * [ed25519](https://pub.dev/documentation/cryptography/latest/cryptography/ed25519-constant.html) (curve25519 EdDSA)
    * In our benchmarks, the performance is around 200 signatures or verifications per second in VM
      (about 50 in browsers).
  * Elliptic curves approved by NIST ([read about the algorithm](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography))
    * [ecdsaP256Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP256Sha256-constant.html) (ECDSA P256 / secp256r1 / prime256v1 + SHA256)
    * [ecdsaP384Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP384Sha256-constant.html) (ECDSA P384 / secp384r1 / prime384v1 + SHA256)
    * [ecdsaP384Sha384](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP384Sha384-constant.html) (ECDSA P384 / secp384r1 / prime384v1 + SHA384)
    * [ecdsaP521Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP521Sha256-constant.html) (ECDSA P521 / secp521r1 / prime521v1 + SHA256)
    * [ecdsaP521Sha512](https://pub.dev/documentation/cryptography/latest/cryptography/ecdsaP521Sha512-constant.html) (ECDSA P521 / secp521r1 / prime521v1 + SHA512)
    * Currently implemented only in browsers.
  * RSA
    * [RsaPss](https://pub.dev/documentation/cryptography/latest/cryptography/RsaPss-class.html) (RSA-PSS)
    * [RsaSsaPkcs1v15](https://pub.dev/documentation/cryptography/latest/cryptography/RsaPkcs1v15-class.html) (RSASSA-PKCS1v15)
    * Currently implemented only in browsers.

### Symmetric encryption
The following [Cipher](https://pub.dev/documentation/cryptography/latest/cryptography/Cipher-class.html) implementations are available:
  * [CipherWithAppendedMac](https://pub.dev/documentation/cryptography/latest/cryptography/CipherWithAppendedMac-class.html)
    adds authentication (such as HMAC-SHA256) to ciphers without built-in authentication.
  * AES ([read about the algorithm](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard))
    * [aesCbc](https://pub.dev/documentation/cryptography/latest/cryptography/aesCbc-constant.html) (AES-CBC)
    * [aesCtr](https://pub.dev/documentation/cryptography/latest/cryptography/aesCtr-constant.html) (AES-CTR)
    * [aesGcm](https://pub.dev/documentation/cryptography/latest/cryptography/aesGcm-constant.html) (AES-GCM)
    * In our benchmarks, the performance is around 10-70 MB/s in VM (about 400MB - 700MB/s in
      browsers).
  * Chacha20 family ([read about the algorithm](https://en.wikipedia.org/wiki/Salsa20))
    * [chacha20](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20-constant.html)
    * [chacha20Poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20Poly1305Aead-constant.html) (AEAD_CHACHA20_POLY1305)
    * [xchacha20](https://pub.dev/documentation/cryptography/latest/cryptography/xchacha20-constant.html)
    * [xchacha20Poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/xchacha20Poly1305Aead-constant.html) (AEAD_XCHACHA20_POLY1305)
    * In our benchmarks, the performance is around 40-140MB/s in VM.

### Password hashing algorithms
  * [Pbkdf2](https://pub.dev/documentation/cryptography/latest/cryptography/Pbkdf2-class.html) (PBKDF2)

### Key derivation algorithms
  * [HChacha20](https://pub.dev/documentation/cryptography/latest/cryptography/HChacha20-class.html)
  * [Hkdf](https://pub.dev/documentation/cryptography/latest/cryptography/Hkdf-class.html) (HKDF)

### Message authentication codes
The following [MacAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/MacAlgorithm-class.html) implementations are available:
  * [Hmac](https://pub.dev/documentation/cryptography/latest/cryptography/Hmac-class.html)
  * [poly1305](https://pub.dev/documentation/cryptography/latest/cryptography/poly1305-constant.html)

### Cryptographic hash functions
The following [HashAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/HashAlgorithm-class.html) implementations are available:
  * [blake2b](https://pub.dev/documentation/cryptography/latest/cryptography/blake2b-constant.html) (BLAKE2B)
  * [blake2s](https://pub.dev/documentation/cryptography/latest/cryptography/blake2s-constant.html) (BLAKE2S)
  * [sha1](https://pub.dev/documentation/cryptography/latest/cryptography/sha1-constant.html) (SHA1)
  * [sha224](https://pub.dev/documentation/cryptography/latest/cryptography/sha224-constant.html) (SHA2-224)
  * [sha256](https://pub.dev/documentation/cryptography/latest/cryptography/sha256-constant.html) (SHA2-256)
  * [sha384](https://pub.dev/documentation/cryptography/latest/cryptography/sha384-constant.html) (SHA2-384)
  * [sha512](https://pub.dev/documentation/cryptography/latest/cryptography/sha512-constant.html) (SHA2-512)

# Adding dependency
In _pubspec.yaml_:
```yaml
dependencies:
  cryptography: ^1.1.1
```


# Examples
## Key agreement with X25519
In this example, we use [x25519](https://pub.dev/documentation/cryptography/latest/cryptography/x25519-constant.html).

```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // Let's generate two X25519 keypairs.
  final localKeyPair = await x25519.newKeyPair();
  final remoteKeyPair = await x25519.newKeyPair();

  // We can now calculate a shared 256-bit secret
  final secretKey = await x25519.sharedSecret(
    localPrivateKey: localKeyPair.privateKey,
    remotePublicKey: remoteKeyPair.publicKey,
  );

  final secretBytes = await secretKey.extract();
  print('Shared secret: $secretBytes');
}
```


## Digital signature with ED25519
In this example, we use [ed25519](https://pub.dev/documentation/cryptography/latest/cryptography/ed25519-constant.html).

```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // The message that we will sign
  final message = <int>[1,2,3];

  // Generate a random ED25519 keypair
  final keyPair = await ed25519.newKeyPair();

  // Sign
  final signature = await ed25519.sign(
    message,
    keyPair,
  );

  print('Signature: ${signature.bytes}');
  print('Public key: ${signature.publicKey.bytes}');

  // Verify signature
  final isSignatureCorrect = await ed25519.verify(
    message,
    signature,
  );

  print('Is the signature correct: $isSignatureCorrect');
}
```


## Authenticated encryption with Chacha20 + Poly1305
In this example, we use [chacha20Poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/chacha20Poly1305Aead-constant.html),
a standard that uses ChaCha20 and Poly1305.

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
  final message = utf8.encode('encrypted message');

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
In this example, we encrypt a message with [aesCtr](https://pub.dev/documentation/cryptography/latest/cryptography/aesCtr-constant.html)
and append a [Hmac](https://pub.dev/documentation/cryptography/latest/cryptography/Hmac-class.html)
message authentication code.

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
  final message = utf8.encode('encrypted message');

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
  final secretKey = SecretKey(utf8.encode('authentication secret'));

  // Create a HMAC-BLAKE2S sink
  final macAlgorithm = const Hmac(blake2s);
  final sink = macAlgorithm.newSink(secretKey: secretKey);

  // Add all parts of the authenticated message
  sink.add([1,2,3]);
  sink.add([4,5]);

  // Calculate MAC
  sink.close();
  final macBytes = sink.mac.bytes;

  print('Message authentication code: $macBytes');
}
```