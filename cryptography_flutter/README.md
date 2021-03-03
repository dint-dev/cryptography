[![Pub Package](https://img.shields.io/pub/v/cryptography_flutter.svg)](https://pub.dev/packages/cryptography_flutter)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview

This is a version of the package [cryptography](https://pub.dev/packages/cryptography) that
optimizes performance of some cryptographic algorithms by using native APIs of Android, iOS, and
Mac OS X. You must use asynchronous methods to get the performance boost.

## Optimized algorithms
### In Android
  * AES_CBC
  * AES_CTR
  * AES_GCM
  * CHACHA20_POLY1305_AEAD

### In iOS and Mac OS X
  * AES_GCM
  * CHACHA20_POLY1305_AEAD

## Links
  * [Github project](https://github.com/dint-dev/cryptography)
  * [Issue tracker](https://github.com/dint-dev/cryptography/issues)
  * [Pub package](https://pub.dev/packages/cryptography_flutter)
  * [API reference](https://pub.dev/documentation/cryptography_flutter/latest/)

# Getting started
In _pubspec.yaml_:
```yaml
dependencies:
  cryptography: ^2.0.0
  cryptography_flutter: ^2.0.0
```

Then just use:
```dart
import 'package:cryptography_flutter/cryptography_flutter.dart';

void main() {
  // Enable Flutter cryptography
  FlutterCryptography.enable();

  // ....
}
```

For APIs, read documentation for [package:cryptography](https://pub.dev/packages/cryptography).

# Contributing?
Test the plugin by running integration tests in
_cryptography_flutter/example/_ (see README in the directory).