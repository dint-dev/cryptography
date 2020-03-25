[![Pub Package](https://img.shields.io/pub/v/kms.svg)](https://pub.dev/packages/kms)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview
This package gives you a vendor-agnostic API for accessing Key Management Service (KMS) products.
Many operating systems and major cloud platforms (AWS, Azure, Google) offer such APIs.

In browser, you can use [MemoryKms](https://pub.dev/documentation/kms/latest/kms/MemoryKms-class.html),
which is our in-memory KMS that runs in all platforms. It uses cryptographic implementations in our
sibling project, [package:cryptography](https://pub.dev/packages/cryptography).

# Getting started
## 1.Add dependency
In _pubspec.yaml_:
```yaml
dependencies:
  kms: ^0.1.0
```

## 2.Use
### For key exchange
```dart
import 'package:kms/kms.dart';

Future<void> main() async {
  final kms = MemoryKms();

  // Create our key pairs
  final kmsKey = await kms.createKeyPair(
    keyRingId: 'example',
    keyExchangeType: KeyExchangeType.ecdhCurve25519, // Enable ECDH-Curve25519
    signatureType: null, // Disable digital signature
  );

  // Generate a Curve25519 public key for the peer.
  // In real life, you receive the public key from some source.
  final peerKmsKey = await kms.createKeyPair(
    keyRingId: 'example',
    keyExchangeType: KeyExchangeType.ecdhCurve25519,
    signatureType: null,
  );
  final peerPublicKey = await kms.getPublicKey(kmsKey1);

  // Generate a shared secret key
  final secretKey = await kms.sharedSecret(kmsKey, peerPublicKey);
  print('Secret key: ${secretKey.bytes}');

  // Delete the key pair
  await kms.delete(kmsKey);
}
```

### For digital signature
```dart
import 'package:kms/kms.dart';

Future<void> main() async {
  final kms = MemoryKms();

  // Create the key pair
  final kmsKey = await kms.createKeyPair(
    keyRingId: 'example',
    keyExchangeType: null, // Disable key exchange
    signatureType: SignatureType.ecdsaP256Sha256, // Enable ECDSA-P256-SHA256
  );

  // Generate a signature
  final data = <int>[1,2,3];
  final signature = await kms.sign(data, kmsKey);
  print('Signature: ${signature.bytes}');
  print('Public key: ${signature.publicKey}');

  // Delete the key pair
  await kms.delete(kmsKey);
}
```