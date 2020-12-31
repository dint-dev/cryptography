[![Pub Package](https://img.shields.io/pub/v/kms.svg)](https://pub.dev/packages/kms)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview
A vendor-agnostic API for storing and using cryptographic keys in Flutter / Dart.

The package can be used for accessing Key Management Service (KMS) APIs such as:
  * Keystore in Android
  * Keychain in iOS and Mac OS X
  * We may add support for services by cloud vendors (AWS KMS, Azure Vault, Google Cloud KMS).

The package uses algorithm implementations from
[package:cryptography](https://pub.dev/packages/cryptography).


## Links
  * [Github project](https://github.com/dint-dev/cryptography)
  * [Issue tracker](https://github.com/dint-dev/cryptography/issues)
  * [Pub package](https://pub.dev/packages/kms)
  * [API reference](https://pub.dev/documentation/kms/latest/)

## Available adapters
  * In this package:
    * [BrowserKms](https://pub.dev/documentation/kms/latest/kms/BrowserKms-class.html)
    * [MemoryKms](https://pub.dev/documentation/kms/latest/kms/MemoryKms-class.html)
  * [kms_flutter](https://pub.dev/packages/kms_flutter)
    * Uses operating system APIs for storing cryptographic keys. Supports Android Keystore and iOS
      Keychain.


# Getting started
## 1.Add dependency
In _pubspec.yaml_:
```yaml
dependencies:
  kms: ^0.4.0
```

## 2.Use
### For digital signature
```dart
import 'package:kms/kms.dart';
import 'package:kms_flutter/kms_flutter';

final kms = flutterKms();

Future<void> main() async {
  final collection = kms.collection('examples');

  // Create the key pair
  final document = await collection.createKeyPair(
    documentId: 'My key pair',
    keyExchangeType: null, // We will not do key exchange.
    signatureType: SignatureType.ed25519,
  );

  // Signed message
  final message = <int>[1,2,3];

  // Request a signature from the KMS
  final signature = await document.sign(message);
  print('Signature: ${signature.bytes}');
  print('Public key: ${signature.publicKey}');

  // Delete the key pair.
  // In real applications, you would store keys for longer time.
  await document.delete();
}
```

### For key agreement
```dart
import 'package:cryptography/cryptography.dart';
import 'package:kms/kms.dart';
import 'package:kms_flutter/kms_flutter';

final kms = flutterKms();

Future<void> main() async {
  final collection = kms.collection('examples');

  // Create a key pair
  final kmsKey = await collection.createKeyPair(
    documentId: 'My key pair',
    keyExchangeType: KeyExchangeType.x25519,
    signatureType: null, // We will not do signing.
  );

  // In this example, our counter-party has some random public key.
  final remotePublicKey = x25519.newKeyPairSync().publicKey;

  // Request a shared secret from the KMS.
  final secretKey = await document.sharedSecretKey(
    remotePublicKey: remotePublicKey,
  );

  print('Secret key: ${secretKey.extractSync()}');

  // Delete the key pair
  await document.delete(kmsKey);
}
```

### For encryption
```dart
import 'package:cryptography/cryptography.dart';
import 'package:kms/kms.dart';
import 'package:kms_flutter/kms_flutter';

final kms = flutterKms();

Future<void> main() async {
  // Create a cryptographic key with ID 'my signing key'
  final document = kms.collection('example').createSecretKey(
    documentId: 'my signing key',
    cipherType: CipherType.aesGcm,
  );

  // Choose some unique nonce (initialization vector, IV)
  final nonce = aesGcm.newNonce();

  // Encrypt
  final encrypted = await document.encrypt(
    'Encrypted data'.codePoints,
    nonce: nonce,
  );

  // Decrypt
  final decrypted = await document.decrypt(
    encrypted,
    nonce: nonce,
  );
}
```

# Supported algorithms
## Key agreement
  * X25519
    * Supported by:
      * Apple APIs
  * ECDH P256
    * Supported by:
      * Apple APIs (including [the Secure Enclave](https://developer.apple.com/documentation/cryptokit/secureenclave/p256)).
      * AWS KMS
      * Azure Vault
      * Google Cloud KMS

## Digital signature
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

## Authenticated ciphers
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
