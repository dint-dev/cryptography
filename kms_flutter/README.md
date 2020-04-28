[![Pub Package](https://img.shields.io/pub/v/kms_flutter.svg)](https://pub.dev/packages/kms_flutter)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview
This is an adapter for the package [kms](https://pub.dev/packages/kms) that uses:
  * Keystore in Android
  * Keychain in iOS and Mac OS X
  * _BrowserKms_ in browsers

Currently the package uses the package [flutter_secure_storage](https://pub.dev/packages/flutter_secure_storage)
for storing the keys. We may transition to direct use of the underlying APIs in the future.

# Getting started
## 1.Add dependency
```yaml
dependencies:
  kms: ^0.4.0
  kms_flutter: ^0.1.0
```

## 2.Set Android minimum version
Your _android/app/build.gradle_ should have minimum SDK version 18 or above:
```
    defaultConfig {
        // ...
        minSdkVersion 18
        // ...
    }
```

## 3.Use
```dart
import 'package:kms/kms';
import 'package:kms_flutter/kms_flutter';

final kms = flutterKms();

Future<void> main() async {
  // Create a key pair
  final document = kms.collection('examples').createKeyPair(
    keyExchangeType: null,
    signatureType: SignatureType.ed25519,
  );

  // Sign a document
  final signature = document.sign([1,2,3]);

  print('Signature: ${signature.bytes}');
  print('Public key: ${signature.publicKey.bytes}');
}
```