[![Pub Package](https://img.shields.io/pub/v/cryptography_plus.svg)](https://pub.dev/packages/cryptography_plus)
[![Github Actions CI](https://github.com/emz-hanauer/dart-cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/emz-hanauer/dart-cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview

Cryptographic packages for [Dart](https://dart.dev) / [Flutter](https://flutter.dev) developers.
Open-sourced under the [Apache License 2.0](LICENSE).

> Package was maintained by [gohilla.com](https://gohilla.com). Repository was moved to [emz-hanauer/dart-cryptography](https://github.com/emz-hanauer/dart-cryptography) due to lack of maintenance.

## Packages

- [cryptography_plus](cryptography)
  - Cryptography API for Dart / Flutter.
  - Contains cryptographic algorithm implementations written in pure Dart.
  - Contains cryptographic algorithm implementations that use Web Cryptography API in browsers.
- [cryptography_flutter_plus](cryptography_flutter)
  - Contains cryptographic algorithm implementations that use operating system APIs in Android
    and Apple operating systems (iOS, Mac OS X, etc.).
- [cryptography_flutter_integration_test](cryptography_flutter_integration_test)
  - Integration test project for "cryptography_flutter".
- [cryptography_test](cryptography_flutter)
  - Cross-platform tests. Note that "cryptography" and "cryptography_flutter_integration_test"
    contain more tests than just these.
- [jwk_plus](jwk)
  - JWK (JSON Web Key) encoding / decoding.

## Contributing

Please share feedback / issue reports in the
[issue tracker](https://github.com/emz-hanauer/dart-cryptography/issues).

Pull requests are welcome.
