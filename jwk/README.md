[![Pub Package](https://img.shields.io/pub/v/jwk.svg)](https://pub.dev/packages/jwk)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview
JWK (JSON Web Key) encoding and decoding. Designed to be used with
[package:cryptography](https://pub.dev/packages/cryptography).

Licensed under the [Apache License 2.0](LICENSE).

# Getting started
In _pubspec.yaml_
```yaml
dependencies:
  cryptography: ^2.7.0
  jwk: ^0.2.4
```

# Examples
## Encoding KeyPair
```dart
import 'package:cryptography/cryptography.dart';
import 'package:jwk/jwk.dart';

Future<void> main() async {
  final keyPair = await RsaPss().newKeyPair();
  final jwk = Jwk.fromKeyPair(keyPair);
  final json = jwk.toJson();
}
```

## Decoding SecretKey
```dart
import 'package:jwk/jwk.dart';

void main() {
  final jwk = Jwk.fromJson({
    'kty': 'OCT',
    'alg': 'A128KW',
    'k': 'GawgguFyGrWKav7AX4VKUg',
  });
  final secretKey = jwk.toSecretKey();
}
```
