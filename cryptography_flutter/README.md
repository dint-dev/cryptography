[![Pub Package](https://img.shields.io/pub/v/cryptography_flutter.svg)](https://pub.dev/packages/cryptography_flutter)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions)

# Overview

This is a version of the package [cryptography](https://pub.dev/packages/cryptography) that
optimizes performance of some cryptographic algorithms by using native APIs of Android, iOS, and
Mac OS X. You must use asynchronous methods to get the performance boost.

Maintained by Gohilla. Licensed under the [Apache License 2.0](LICENSE).

## General behavior
This package contains two kinds of classes:
  * Classes such as [FlutterChacha20](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/FlutterChacha20-class.html)
    use operating system APIs in Android / iOS / Mac OS X. If the operating system does not support
    the algorithm, the background implementation (such as `BackgroundChacha20`) or a pure Dart
    implementation (such as [DartChacha20](https://pub.dev/documentation/cryptography/latest/cryptography.dart/DartChacha20-class.html))
    when available.
  * Classes such as [BackgroundChacha20](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/BackgroundChacha20-class.html)
    move the computation away from the UI isolate using [compute](https://api.flutter.dev/flutter/foundation/compute-constant.html)
    ("package:flutter/foundation.dart").

Both compute very small inputs in the same isolate if the overhead of message passing does not
make sense. For example, if you encrypt a 16 byte message, the computation is done in the same
isolate. Too large inputs are also computed in the same isolate (because you probably should not
allocate a gigabyte cross-isolate message on a mobile phone). We also have a queue to prevent memory
exhaustion that could happen if you send lots of requests concurrently (something we observed
during testing).

# Getting started
In _pubspec.yaml_:
```yaml
dependencies:
  cryptography: ^2.3.0
  cryptography_flutter: ^2.2.0
```

That's it!

For API documentation, read more at [pub.dev/packages/cryptography](https://pub.dev/packages/cryptography).

# Optimizations by platform
## In iOS and Mac OS X
Calling `FlutterCryptography.enable()` enables:
  * [FlutterAesGcm](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/FlutterAesGcm-class.html)
    * Our benchmarks have shown up to ~50 times better performance.
  * [FlutterChacha20](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/FlutterChacha20-class.html)
    * Our benchmarks have shown up to ~10 times better performance.
  * [FlutterEd25519](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/FlutterEd25519-class.html)
    * Our benchmarks have shown up to ~10 times better performance.
  * [FlutterX25519](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/FlutterX25519-class.html)
    * Our benchmarks have shown up to ~10 times better performance.

By default, maximum input size is 100 MB.

## In Android
We have observe problems with some Android devices. Therefore we have disabled some optimizations
until we have time to investigate the problems.

Calling `FlutterCryptography.enable()` enables:
* [FlutterAesGcm](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/FlutterAesGcm-class.html) 
  * Our benchmarks have shown up to ~50 times better performance.
* [FlutterChacha20](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/FlutterChacha20-class.html)
  * Our benchmarks have shown up to ~10 times better performance.
* [BackgroundEd25519](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/BackgroundEd25519-class.html)
* [BackgroundX25519](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/BackgroundX25519-class.html)

By default, maximum input size is 20 MB because of memory allocation crashes we observed during
testing.

## In other platforms
In browsers, nothing is changed.

In Windows, Linux, and other platforms:
* [BackgroundAesGcm](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/BackgroundAesGcm-class.html)
* [BackgroundChacha20](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/BackgroundChacha20-class.html)
* [BackgroundEd25519](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/BackgroundEd25519-class.html)
* [BackgroundX25519](https://pub.dev/documentation/cryptography_flutter/latest/cryptography_flutter/BackgroundX25519-class.html)

## Links
* [Github project](https://github.com/dint-dev/cryptography)
* [Issue tracker](https://github.com/dint-dev/cryptography/issues)
* [Pub package](https://pub.dev/packages/cryptography_flutter)
* [API reference](https://pub.dev/documentation/cryptography_flutter/latest/)
