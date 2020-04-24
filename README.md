[![Pub Package](https://img.shields.io/pub/v/cryptography.svg)](https://pub.dev/packages/cryptography)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview

Cryptographic packages for [Dart](https://dart.dev) developers.

Key features:
  * __Supports modern algorithms__. The package supports new popular algorithms such as
    Curve25519 and Chacha20 as well as old NIST standards such as AES.
  * __Enterprise-friendly__. This package uses Apache 2.0 License and is supported by a commercial
    company. Whenever possible (currently SHA1, SHA2), we use implementations by Google. We wrote
    decent tests for algorithms we had to implement ourselves.
  * __Easy-to-use__. To make the world a safer place, we wrote an API that pushes non-expert
    developers to use cryptography correctly.

Copyright 2020 Gohilla Ltd. Licensed under the [Apache License 2.0](LICENSE).

# Packages
  * [cryptography](cryptography)
    * Covers:
      * Key exchange algorithms
      * Digital signature algorithms
      * Encryption algorithms
      * Message authentication codes
      * Hashes
    * [Pub package](https://pub.dev/packages/cryptography)
    * [API reference](https://pub.dev/documentation/cryptography/latest/)
  * [kms](kms)
    * A framework for Key Management Service (KMS) solutions.
    * [Pub package](https://pub.dev/packages/kms)
    * [API reference](https://pub.dev/documentation/kms/latest/)
  * [kms_adapter_cupertino](kms_adapter_cupertino)
    * An adapter for using iOS / Mac OS X key management APIs.

# Want to contribute?
  * Any help is appreciated! We recommend that you start by creating an issue in the
    [issue tracker](https://github.com/dint-dev/cryptography/issues).
  * Show love by starring the package [in Github](https://github.com/dint-dev/cryptography). ;)