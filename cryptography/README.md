[![Pub Package](https://img.shields.io/pub/v/cryptography.svg)](https://pub.dev/packages/cryptography)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions)

# Overview

Popular cryptographic algorithms for [Dart](https://dart.dev) / [Flutter](https://flutter.dev)
developers.

Maintained by [gohilla.com](https://gohilla.com). Licensed under the [Apache License 2.0](LICENSE).

This package is designed to be:

* __Easy to use__. The API is easy to understand and encourages good defaults.
* __Multi-platform__. It's easy to customize implementation of X in platform Y.
* __Fast.__ We use platform APIs when available. For example, SHA-512 is over 100 times faster than
  _package:crypto_ in browsers.

Any feedback, issue reports, or pull requests are appreciated!

## Links

* [Github project](https://github.com/dint-dev/cryptography)
* [Issue tracker](https://github.com/dint-dev/cryptography/issues)
* [Pub package](https://pub.dev/packages/cryptography)
* [API reference](https://pub.dev/documentation/cryptography/latest/)

# Getting started

If you use Flutter, it's recommended (but not necessarily) that you also import our sibling package
[cryptography_flutter](https://pub.dev/packages/cryptography_flutter), which delegates calls to
Android / iOS / Mac OS X operating system APIs whenever possible.

In _pubspec.yaml_:
```yaml
dependencies:
  cryptography: ^2.7.0
  cryptography_flutter: ^2.3.2 # Remove if you don't use Flutter
```

You are ready to go!

# Issues and discussions

Please report bugs at [github.com/dint-dev/cryptography/issues](https://github.com/dint-dev/cryptography/issues).

Having questions? Feel free to use our Github Discussions at
[github.com/dint-dev/cryptography/discussions](https://github.com/dint-dev/cryptography/discussions).


# Some things to know
## General guidance on cryptography
Please read [information about Mobile App Cryptography](https://mas.owasp.org/MASTG/General/0x04g-Testing-Cryptography/)
by OWASP. It contains a lot of useful information that helps you build more secure software.

## Common parameters
* [SecretKey](https://pub.dev/documentation/cryptography/latest/cryptography/SecretKey-class.html)
    * Used by ciphers, message authentication codes, and key derivation functions.
* [KeyPair](https://pub.dev/documentation/cryptography/latest/cryptography/KeyPair-class.html)
    * [SimpleKeyPair](https://pub.dev/documentation/cryptography/latest/cryptography/SimpleKeyPair-class.html)
      (Octet sequences such as Ed25519 / X25519 32-byte private keys)
    * [EcKeyPairData](https://pub.dev/documentation/cryptography/latest/cryptography/EcKeyPair-class.html)
      (P-256, P-384, P-521 private keys)
    * [RsaKeyPairData](https://pub.dev/documentation/cryptography/latest/cryptography/RsaKeyPair-class.html)
      (RSA private keys)
* [PublicKey](https://pub.dev/documentation/cryptography/latest/cryptography/PublicKey-class.html)
    * [SimplePublicKey](https://pub.dev/documentation/cryptography/latest/cryptography/SimplePublicKey-class.html)
      (Octet sequences such as Ed25519 / X25519 32-byte public keys)
    * [EcPublicKey](https://pub.dev/documentation/cryptography/latest/cryptography/EcPublicKey-class.html)
      (P-256 / P-384 / P-512 public keys)
    * [RsaPublicKey](https://pub.dev/documentation/cryptography/latest/cryptography/RsaPublicKey-class.html)
      (RSA public keys)

Note that SecretKey and KeyPair instances are opaque and asynchronous by default. They may not be in
the memory and may not be readable at all. If a SecretKey or KeyPair instance is in memory, it's an
instance of one of the following:
* [SecretKeyData](https://pub.dev/documentation/cryptography/latest/cryptography/SecretKeyData-class.html)
* [SimpleKeyPairData](https://pub.dev/documentation/cryptography/latest/cryptography/SimpleKeyPairData-class.html)
* [EcKeyPairData](https://pub.dev/documentation/cryptography/latest/cryptography/EcKeyPairData-class.html)
* [RsaKeyPairData](https://pub.dev/documentation/cryptography/latest/cryptography/RsaKeyPairData-class.html)

For encoding/decoding private/public keys in JWK (JSON Web Key) format, use
[package:jwk](https://pub.dev/packages/jwk).
For encoding/decoding X.509, PKCS12, and other formats, we don't have recommended packages
at the moment.

## Wands (recommended)

For a bit higher API abstraction and sometimes a performance boost, we encourage developers to use
[Wand](https://pub.dev/documentation/cryptography/latest/cryptography/Wand-class.html)
instances which do operations with fixed, "invisible" key (thus "magic wands"). There are currently
three types of wands:
* [CipherWand](https://pub.dev/documentation/cryptography/latest/cryptography/CipherWand-class.html)
* [KeyExchangeWand](https://pub.dev/documentation/cryptography/latest/cryptography/KeyExchangeWand-class.html)
* [SignatureWand](https://pub.dev/documentation/cryptography/latest/cryptography/SignatureWand-class.html)

In the future version 3.x, we plan to transition to wands as the default API for doing operations.

## Ciphers

The following [Cipher](https://pub.dev/documentation/cryptography/latest/cryptography/Cipher-class.html)
implementations are available:

* AES
    * [AesCbc](https://pub.dev/documentation/cryptography/latest/cryptography/AesCbc-class.html) (
      AES-CBC)
        * The throughput is up to 120 MB / second (Macbook Pro, message size 1 MB).
    * [AesCtr](https://pub.dev/documentation/cryptography/latest/cryptography/AesCtr-class.html) (
      AES-CTR)
        * The throughput is up to 80 MB / second (Macbook Pro, message size 1 MB).
    * [AesGcm](https://pub.dev/documentation/cryptography/latest/cryptography/AesGcm-class.html) (
      AES-GCM)
        * The throughput is up to 20 MB / second (Macbook Pro, message size 1 MB).
    * In browsers, the package uses Web Cryptography, reaching over 500 MB/s.
* ChaCha20 / XChaCha20
    * [Chacha20](https://pub.dev/documentation/cryptography/latest/cryptography/Chacha20-class.html)
        * The throughput is up to 230 MB / second (Macbook Pro, message size 1 MB).
    * [Chacha20.poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/Chacha20/Chacha20.poly1305Aead.html) (
      AEAD_CHACHA20_POLY1305)
        * The throughput is up to 30 MB / second (Macbook Pro, message size 1 MB).
    * [Xchacha20](https://pub.dev/documentation/cryptography/latest/cryptography/Xchacha20-class.html)
    * [Xchacha20.poly1305Aead](https://pub.dev/documentation/cryptography/latest/cryptography/Xchacha20/Xchacha20.poly1305Aead.html) (
      AEAD_XCHACHA20_POLY1305)

## Digital signature algorithms

The
following [SignatureAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/SignatureAlgorithm-class.html)
implementations are available:

* [Ed25519](https://pub.dev/documentation/cryptography/latest/cryptography/Ed25519-class.html) (
  curve25519 EdDSA)
    * Performance of the pure Dart implementation is around 200 (signatures or verifications) per
      second in VM and about 50 in browsers.
* Elliptic curves approved by NIST
    * [Ecdsa.p256](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdsa/Ecdsa.p256.html) (
      ECDSA P256 / secp256r1 / prime256v1 + SHA256)
    * [Ecdsa.p384](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdsa/Ecdsa.p384.html) (
      ECDSA P384 / secp384r1 / prime384v1 + SHA384)
    * [Ecdsa.p521](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdsa/Ecdsa.p521.html) (
      ECDSA P521 / secp521r1 / prime521v1 + SHA256)
    * We don't have implementations of these in pure Dart.
* RSA
    * [RsaPss](https://pub.dev/documentation/cryptography/latest/cryptography/RsaPss-class.html) (
      RSA-PSS)
    * [RsaSsaPkcs1v15](https://pub.dev/documentation/cryptography/latest/cryptography/RsaSsaPkcs1v15-class.html) (
      RSASSA-PKCS1v15)
    * We don't have implementations of these in pure Dart.

## Key exchange algorithms

The following [KeyExchangeAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/KeyExchangeAlgorithm-class.html)
implementations are available:

* Elliptic curves approved by NIST
    * [Ecdh.p256](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdh/Ecdh.p256.html) (
      ECDH P256 / secp256r1 / prime256v1)
    * [Ecdh.p384](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdh/Ecdh.p384.html) (
      ECDH P384 / secp384r1 / prime384v1)
    * [Ecdh.p521](https://pub.dev/documentation/cryptography/latest/cryptography/Ecdh/Ecdh.p521.html) (
      ECDH P521 / secp521r1 / prime521v1)
    * We don't have implementations of these in pure Dart.
* [X25519](https://pub.dev/documentation/cryptography/latest/cryptography/X25519-class.html) (
  curve25519 Diffie-Hellman)
    * Throughput of the pure Dart implementation is around 1000 key agreements per second (in VM).

### Key derivation / password hashing algorithms

The following [KdfAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/KdfAlgorithm-class.html) implementations are available:

* [Hchacha20](https://pub.dev/documentation/cryptography/latest/cryptography/Hchacha20-class.html)
* [Hkdf](https://pub.dev/documentation/cryptography/latest/cryptography/Hkdf-class.html)
* [Pbkdf2](https://pub.dev/documentation/cryptography/latest/cryptography/Pbkdf2-class.html)
* [Argon2id](https://pub.dev/documentation/cryptography/latest/cryptography/Argon2id-class.html)
  * Argon2id is the recommended algorithm for password hashing.

## Message authentication codes

The following [MacAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/MacAlgorithm-class.html)
implementations are available:

* [Blake2b](https://pub.dev/documentation/cryptography/latest/cryptography/Blake2b-class.html)
* [Blake2s](https://pub.dev/documentation/cryptography/latest/cryptography/Blake2s-class.html)
* [Hmac](https://pub.dev/documentation/cryptography/latest/cryptography/Hmac-class.html)
* [Poly1305](https://pub.dev/documentation/cryptography/latest/cryptography/Poly1305-class.html)

## Cryptographic hash functions

The following [HashAlgorithm](https://pub.dev/documentation/cryptography/latest/cryptography/HashAlgorithm-class.html)
implementations are available:

* [Blake2b](https://pub.dev/documentation/cryptography/latest/cryptography/Blake2b-class.html)
  (BLAKE2B)
* [Blake2s](https://pub.dev/documentation/cryptography/latest/cryptography/Blake2s-class.html)
  (BLAKE2S)
* [Sha1](https://pub.dev/documentation/cryptography/latest/cryptography/Sha1-class.html) (SHA1)
* [Sha224](https://pub.dev/documentation/cryptography/latest/cryptography/Sha224-class.html)
  (SHA2-224)
* [Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/Sha256-class.html)
  (SHA2-256)
* [Sha384](https://pub.dev/documentation/cryptography/latest/cryptography/Sha384-class.html)
  (SHA2-384)
* [Sha512](https://pub.dev/documentation/cryptography/latest/cryptography/Sha512-class.html)
  (SHA2-512)

The performance is excellent! Our pure Dart implementation of Sha256 is around 2 times faster than
implementation in the older "package:crypto" because of inlining and smarter integer use. If you do
lots of small hashes, the advantage is even bigger because this package allows you re-use the hash
state. Therefore our HMAC-SHA256 is much faster too. In browsers, hashes can be over 100 times
faster because this package automatically uses Web Crypto API.

## Random number generators

We use Dart SDK [Random.secure()](https://api.dart.dev/stable/3.1.0/dart-math/Random/Random.secure.html)
as the default random number in all APIs.

If you do want much faster cryptographically reasonably strong random numbers, this package contains
[SecureRandom.fast](https://pub.dev/documentation/cryptography/latest/cryptography/SecureRandom/fast.html).
It generates random numbers by using 12 round version ChaCha cipher. It can generate up to 0.25 GB
random data per second because it makes expensive operating system call less frequently after the
initial seeding from the operating system. While ChaCha is not designed to be a cryptographic random
number generator, it can be acceptable and a related (Blake2-based) RNG is used by Linux kernel.

If you need a deterministic random number generator for tests, the package contains
[SecureRandom.forTesting](https://pub.dev/documentation/cryptography/latest/cryptography/SecureRandom/SecureRandom.forTesting.html),
which uses the aforementioned ChaCha-based RNG with a fixed seed and no re-seeding.

## Cryptographic factory class

The class [Cryptography](https://pub.dev/documentation/cryptography/latest/cryptography/Cryptography-class.html)
has factory methods that return implementations of cryptographic algorithms. The default
implementation is _BrowserCryptography_ (which works in all platforms, not just browser).

We wrote the following three implementations of `Cryptography`:

* [DartCryptography](https://pub.dev/documentation/cryptography/latest/cryptography.dart/DartCryptography-class.html)
    * Gives you implementations written in pure Dart implementations. They work in all platforms.
    * The algorithms are written and tested by us. They are are licensed under the Apache 2.0 License.
    * See the [class documentation](https://pub.dev/documentation/cryptography/latest/cryptography.dart/DartCryptography-class.html)
      for list algorithms supported by it.
* [BrowserCryptography](https://pub.dev/documentation/cryptography/latest/cryptography/BrowserCryptography-class.html)
    * Uses [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
      (_crypto.subtle_) whenever possible. Methods return pure Dart implementations when Web
      Cryptography API is not available.
    * See the [class documentation](https://pub.dev/documentation/cryptography/latest/cryptography/BrowserCryptography-class.html)
      for list algorithms supported by it.
* [FlutterCryptography](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/FlutterCryptography-class.html)
    * Makes cryptographic algorithms up to 100 times faster in Android, iOS, and Mac OS X.
    * Available in the package [cryptography_flutter](https://pub.dev/packages/cryptography_flutter).
    * See the [class documentation](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/FlutterCryptography-class.html)
      for list algorithms supported by it.

## Deterministic behavior in tests
If you want to have deterministic behavior in tests, you can supply your own random number
generator:

For example:
```dart
import 'package:cryptography/cryptography.dart';

void main() {
  setUp(() {
    Cryptography.instance = Cryptography.instance.withRandom(SecureRandom.forTesting(seed: 42));
  });
  
  test('example', () async {
    final algorithm = AesGcm.with256bits();
    
    // This will will always return the same secret key.
    // because we use a deterministic random number generator.
    final secretKey = await algorithm.newSecretKey();
    
    // ...
  });
}
```

# Examples

## Digital signature

In this example, we use
[Ed25519](https://pub.dev/documentation/cryptography/latest/cryptography/Ed25519-class.html),
a popular signature algorithm:

```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // The message that we will sign
  final message = <int>[1, 2, 3];

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

In this example, we
use [X25519](https://pub.dev/documentation/cryptography/latest/cryptography/X25519-class.html),
a popular key agreement algorithm:

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
  final sharedSecretBytes = await sharedSecret.extractBytes();
  print('Shared secret: $sharedSecretBytes');
}
```

## Authenticated encryption
When you encrypt, you need:
* Clear text (bytes you are encrypting)
* [SecretKey](https://pub.dev/documentation/cryptography/latest/cryptography/SecretKey-class.html).
  You can generate a random secret key with
  [cipher.newSecretKey()](https://pub.dev/documentation/cryptography/latest/cryptography/Cipher/newSecretKey.html).
* An optional _nonce_ (also known as "IV", "Initialization Vector", "salt"), which is some
  non-secret byte sequence that MUST be unique each time you encrypt. If you don't provide a
  nonce, a random nonce will be automatically generated for you.

The output of encrypting is [SecretBox](https://pub.dev/documentation/cryptography/latest/cryptography/SecretBox-class.html)
that contains the nonce, the cipher text (the encrypted message), and
[Mac](https://pub.dev/documentation/cryptography/latest/cryptography/Mac-class.html) (a message
authentication code).

When you decrypt, you need the _SecretBox_ and the secret key.

In the following example, we encrypt a message
with [AesGcm](https://pub.dev/documentation/cryptography/latest/cryptography/AesGcm-class.html):
```dart
import 'dart:convert';
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // Choose the cipher
  final algorithm = AesGcm.with256bits();

  // Generate a random secret key.
  final secretKey = await algorithm.newSecretKey();
  final secretKeyBytes = await secretKey.extractBytes();
  print('Secret key: ${secretKeyBytes}');

  // Encrypt
  final secretBox = await algorithm.encryptString(
    'Hello!',
    secretKey: secretKey,
  );
  print('Nonce: ${secretBox.nonce}'); // Randomly generated nonce
  print('Ciphertext: ${secretBox.cipherText}'); // Encrypted message
  print('MAC: ${secretBox.mac}'); // Message authentication code
  
  // If you are sending the secretBox somewhere, you can concatenate all parts of it:
  final concatenatedBytes = secretBox.concatenation();
  print('All three parts concatenated: $concatenatedBytes');

  // Decrypt
  final clearText = await algorithm.decryptString(
    secretBox,
    secretKey: secretKey,
  );
  print('Cleartext: $clearText'); // Hello!
}
```

## Password hashing
In this example, we use [Argon2id](https://pub.dev/documentation/cryptography/latest/cryptography/Argon2id-class.html):
```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  final algorithm = Argon2id(
    memory: 10*1000, // 10 MB
    parallelism: 2, // Use maximum two CPU cores.
    iterations: 1, // For more security, you should usually raise memory parameter, not iterations.
    hashLength: 32, // Number of bytes in the returned hash
  );
  
  final secretKey = await algorithm.deriveKeyFromPassword(
    password: 'qwerty',
    nonce: [1, 2, 3],
  );
  final secretKeyBytes = await secretKey.extractBytes();

  print('Hash: ${secretKeyBytes}');
}
```

## Hashing
In this example, we use [Sha256](https://pub.dev/documentation/cryptography/latest/cryptography/Sha256-class.html):
```dart
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  final sink = Sha256().newHashSink();

  // Add all parts of the authenticated message
  sink.add([1, 2, 3]);
  sink.add([4, 5]);
  sink.add([6]);

  // Calculate hash
  sink.close();
  final hash = await sink.hash();

  print('SHA-512 hash: ${hash.bytes}');
}
```
