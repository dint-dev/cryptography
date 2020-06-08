[![Pub Package](https://img.shields.io/pub/v/cryptography_flutter.svg)](https://pub.dev/packages/cryptography_flutter)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview

This is a version of the package [cryptography](https://pub.dev/packages/cryptography) that
optimizes performance of some cryptographic algorithms by using native APIs of Android, iOS, and
Mac OS X. You must use asynchronous methods to get the performance boost.

## Optimized algorithms
### In Android
  * None yet.

### In iOS / Mac OS X
  * aesGcm (AES-GCM)
  * chacha20Poly1305Aead

## Links
  * [Github project](https://github.com/dint-dev/cryptography)
  * [Issue tracker](https://github.com/dint-dev/cryptography/issues)
  * [Pub package](https://pub.dev/packages/cryptography_flutter)
  * [API reference](https://pub.dev/documentation/cryptography_flutter/latest/)

# Getting started
In _pubspec.yaml_:
```yaml
dependencies:
  cryptography_flutter: ^1.4.0
```

Then just use:
```dart
import 'package:cryptography_flutter/cryptography.dart';
```

For more instructions, read documentation for [cryptography](https://pub.dev/packages/cryptography).

# Contributing?
## Testing
Run "no plugin available" tests:
```
flutter test
```

Run e2e tests:
```
cd example
flutter driver test/cryptography_flutter_e2e.dart
```