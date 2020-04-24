[![Pub Package](https://img.shields.io/pub/v/kms.svg)](https://pub.dev/packages/kms)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview
This package gives you a vendor-agnostic API for accessing Key Management Service (KMS) products.
Many operating systems and major cloud platforms (AWS, Azure, Google) offer such APIs.
KMS adapters are subclasses of [Kms](https://pub.dev/documentation/kms/latest/kms/Kms-class.html).

Using the package? Please star [our Github project](https://github.com/dint-dev/cryptography). :)

Copyright 2020 Gohilla Ltd. Licensed under the [Apache License 2.0](LICENSE).

## Links
  * [Github project](https://github.com/dint-dev/cryptography)
  * [Issue tracker](https://github.com/dint-dev/cryptography/issues)
  * [Pub package](https://pub.dev/packages/kms)
  * [API reference](https://pub.dev/documentation/kms/latest/)

## Contributing?
  * We recommend that you start by creating an issue in the
    [issue tracker](https://github.com/dint-dev/cryptography/issues).

## Available adapters
  * [MemoryKms](https://pub.dev/documentation/kms/latest/kms/MemoryKms-class.html)
    * Works in all platforms. It uses cryptographic algorithm implementations from our sibling
      project, [package:cryptography](https://pub.dev/packages/cryptography).
  * `CupertinoKms` (work-in-progress)
    * Uses Apple Security Framework. Uses Secure Enclave (a hardware-based key manager) when
      possible.
  * _Have an adapter? Let us know so we will add a link here._

## Supported algorithms
### Key agreement
  * X25519
    * Supported by:
      * Apple APIs
  * ECDH P256
    * Supported by:
      * Apple APIs (including [the Secure Enclave](https://developer.apple.com/documentation/cryptokit/secureenclave/p256)).
      * AWS KMS
      * Azure Vault
      * Google Cloud KMS

### Digital signature
  * ED25519
    * Supported by:
      * Apple APIs
      * Hashcorp Vault
  * ECDSA P256 + SHA256
    * Supported by:
      * Apple APIs (including [the Secure Enclave](https://developer.apple.com/documentation/cryptokit/secureenclave/p256)).
      * AWS KMS
      * Azure Vault
      * Google Cloud KMS
      * Hashcorp Vault

### Authenticated ciphers
  * AES-GCM
    * Supported by:
      * Apple APIs
      * AWS KMS
      * Azure Vault
      * Google Cloud KMS
      * Hashcorp Vault
  * CHACHA20 + POLY1305
    * Supported by:
      * Apple APIs
      * Hashcorp Vault

# Getting started
## 1.Add dependency
In _pubspec.yaml_:
```yaml
dependencies:
  kms: ^0.3.0
```

## 2.Use
### For digital signature
```dart
import 'package:kms/kms.dart';

Future<void> main() async {
  final kms = MemoryKms();

  // Create the key pair
  final kmsKey = await kms.createKeyPair(
    keyRingId: 'example',
    keyExchangeType: null, // We will not do key exchange.
    signatureType: SignatureType.ed25519,
  );

  // Signed message
  final message = <int>[1,2,3];

  // Request a signature from the KMS
  final signature = await kms.sign(
    message: message,
    kmsKey: kmsKey,
    signatureType: SignatureType.ed25519,
  );

  print('Signature: ${signature.bytes}');
  print('Public key: ${signature.publicKey}');

  // Delete the key pair
  await kms.delete(kmsKey);
}
```

### For key exchange
```dart
import 'package:cryptography/cryptography.dart';
import 'package:kms/kms.dart';

Future<void> main() async {
  final kms = MemoryKms();

  // Create a key pair
  final kmsKey = await kms.createKeyPair(
    keyRingId: 'example',
    keyExchangeType: KeyExchangeType.x25519,
    signatureType: null, // We will not do signing.
  );

  // A random public key for the peer.
  final remotePublicKey = x25519.newKeyPairSync().publicKey;

  // Request a shared secret from the KMS.
  final secretKey = await kms.sharedSecret(
    kmsKey: kmsKey,
    remotePublicKey: remotePublicKey,
    keyExchangeType: KeyExchangeType.x25519,
  );

  print('Secret key: ${secretKey.bytes}');

  // Delete the key pair
  await kms.delete(kmsKey);
}
```