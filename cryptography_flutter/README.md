[![Pub Package](https://img.shields.io/pub/v/cryptography_flutter_plus.svg)](https://pub.dev/packages/cryptography_flutter_plus)
[![Github Actions CI](https://github.com/emz-hanauer/dart-cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/emz-hanauer/dart-cryptography/actions)

# Overview

This is a Flutter plugin that
enables [pub.dev/packages/cryptography_plus](https://pub.dev/packages/cryptography_plus)
to use native APIs of Android, iOS, and Mac OS X.

> Package was maintained by [gohilla.com](https://gohilla.com). Repository was moved to [emz-hanauer/dart-cryptography](https://github.com/emz-hanauer/dart-cryptography) due to lack of maintenance.

Licensed under the [Apache License 2.0](LICENSE).

## Why?

- **Secure**
  - Operating system APIs are preferable from security point of view.
- **Performant**.
  - Operating system APIs are up to 100 times faster than pure Dart implementations.
- **Cross-platform**.
  - The implementations fall back to "package:cryptography" implementations when operating system
    APIs can't be used.

## General behavior

The package is tested with [cryptography_test](https://github.com/emz-hanauer/dart-cryptography/cryptography_test).

This package contains two kinds of classes:

- Classes such
  as [FlutterChacha20](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/FlutterChacha20-class.html)
  use operating system APIs in Android / iOS / Mac OS X. If the operating system does not support
  the algorithm, the background implementation (such as `BackgroundChacha20`) or a pure Dart
  implementation (such
  as [DartChacha20](https://pub.dev/documentation/cryptography_plus/latest/cryptography_plus.dart/DartChacha20-class.html))
  when available.
- Classes such
  as [BackgroundChacha20](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/BackgroundChacha20-class.html)
  move lengthy computations to a background isolate by using
  [compute](https://api.flutter.dev/flutter/foundation/compute-constant.html) function in Flutter
  SDK.
- Both compute very small inputs in the same isolate if the overhead of message passing does not
  make sense. For example, if you encrypt a 16 byte message, the computation is done in the same
  isolate.
- Too large inputs are also computed in the same isolate (because you probably should not
  allocate a gigabyte cross-isolate message on a mobile phone).
- We also have a queue to prevent memory exhaustion that could happen if you send lots of requests
  concurrently.

# Getting started

In _pubspec.yaml_:

```yaml
dependencies:
  cryptography_plus: ^2.7.0
  cryptography_flutter: ^2.3.2
```

That's it!

For API documentation, read more
at [pub.dev/packages/cryptography](https://pub.dev/packages/cryptography).

# Behavior by algorithm

## AES-GCM

[FlutterAesGcm](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/FlutterAesGcm-class.html)
is used in Android, iOS, and Mac OS X.
Our benchmarks have shown up to ~50 times better performance than
[DartAesGcm](https://pub.dev/documentation/cryptography_plus/latest/cryptography_plus.dart/DartAesGcm-class.html)
(the pure Dart implementation).

[BackgroundAesGcm](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/BackgroundAesGcm-class.html)
is used in Windows and Linux for inputs that are large enough.

## ChaCha20-Poly1305-AEAD

[FlutterChacha20](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/FlutterChacha20-class.html)
is available for Android and Apple operating systems.
Our benchmarks have shown up to ~50 times better performance than
[DartChacha20](https://pub.dev/documentation/cryptography_plus/latest/cryptography_plus.dart/DartChacha20-class.html)
(the pure Dart implementation).

[BackgroundChacha20](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/BackgroundChacha20-class.html)
is used in Windows and Linux for inputs that are large enough.

## NIST ECDH / ECDSA

[FlutterEcdh](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/FlutterEcdh-class.html)
and [FlutterEcdsa](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/FlutterEcdsa-class.html)
are available for Apple operating systems.

## Ed25519

[FlutterEd25519](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/FlutterEd25519-class.html)
and [BackgroundEd25519](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/BackgroundEd25519-class.html)
are available for Apple operating systems.

## X25519

[FlutterX25519](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/FlutterX25519-class.html)
and [BackgroundX25519](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/BackgroundX25519-class.html)
are available for Apple operating systems.

## HMAC

[FlutterHmac](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/FlutterHmac-class.html)
is available for Android..

## PBKDF2

[FlutterPbkdf2](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/FlutterPbkdf2-class.html)
is available for Android.
[BackgroundPbkdf2](https://pub.dev/documentation/cryptography_flutter_plus/latest/cryptography_flutter/BackgroundPbkdf2-class.html)
is used in Apple operating systems, Windows and Linux.

## Links

- [Github project](https://github.com/emz-hanauer/dart-cryptography)
- [Issue tracker](https://github.com/emz-hanauer/dart-cryptography/issues)
- [Pub package](https://pub.dev/packages/cryptography_flutter_plus)
- [API reference](https://pub.dev/documentation/cryptography_flutter_plus/latest/)
