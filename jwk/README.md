[![Pub Package](https://img.shields.io/pub/v/jwk_plus.svg)](https://pub.dev/packages/jwk_plus)
[![Github Actions CI](https://github.com/emz-hanauer/dart-cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/emz-hanauer/dart-cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview

JWK plus (JSON Web Key) encoding and decoding. Designed to be used with
[package:cryptography_plus](https://pub.dev/packages/cryptography_plus).

Licensed under the [Apache License 2.0](LICENSE).

# Getting started

In _pubspec.yaml_

```yaml
dependencies:
  cryptography_plus: ^2.7.0
  jwk_plus: ^0.2.4
```

# Examples

## Encoding KeyPair

```dart
import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:jwk_plus/jwk_plus.dart';

Future<void> main() async {
  final keyPair = await RsaPss().newKeyPair();
  final jwk = Jwk.fromKeyPair(keyPair);
  final json = jwk.toJson();
}
```

## Decoding SecretKey

```dart
import 'package:jwk_plus/jwk_plus.dart';

void main() {
  final jwk = Jwk.fromJson({
    'kty': 'OCT',
    'alg': 'A128KW',
    'k': 'GawgguFyGrWKav7AX4VKUg',
  });
  final secretKey = jwk.toSecretKey();
}
```
