// Copyright 2019-2020 Gohilla.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';

import 'package:cryptography_plus/cryptography_plus.dart';

/// An digital signature algorithm that supports [newKeyPair()], [sign()],
/// [verify()].
///
/// ## Available algorithms
///   * [Ecdsa.p256]
///   * [Ecdsa.p384]
///   * [Ecdsa.p521]
///   * [Ed25519]
///   * [RsaPss]
///   * [RsaSsaPkcs1v15]
///
/// ## Example
/// In this example, we use [Ed25519]:
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final signedMessage = 'Hello, world!';
///
///   final ed25519 = Ed25519();
///   final keyPair = await ed25519.newKeyPair();
///   final signature = await ed25519.signString(
///     signedMessage,
///     keyPair: keyPair,
///   );
///
///   // ...
///
///   final isRealSignature = await ed25519.verifyString(
///     signedMessage,
///     signature: signature,
///   );
///
///   print('Signature verification result: $isRealSignature');
/// }
/// ```
abstract class SignatureAlgorithm<T extends PublicKey> {
  const SignatureAlgorithm();

  KeyPairType get keyPairType;

  /// Generates a new [KeyPair] for this algorithm.
  Future<KeyPair> newKeyPair();

  /// Generates a new [KeyPair] that uses the seed bytes.
  ///
  /// This will throw [UnsupportedError] if the algorithm does not support
  /// seeds for private key generation.
  Future<KeyPair> newKeyPairFromSeed(List<int> seed) {
    throw UnsupportedError(
      'newKeyPairFromSeed() is unsupported by this algorithm',
    );
  }

  /// Generates a new [SignatureWand] that has a random [KeyPair].
  Future<SignatureWand> newSignatureWand() async {
    final keyPair = await newKeyPair();
    return newSignatureWandFromKeyPair(keyPair);
  }

  /// Generates a new [SignatureWand] that uses the given [KeyPair].
  Future<SignatureWand> newSignatureWandFromKeyPair(KeyPair keyPair) async {
    return _SignatureWand(this, keyPair);
  }

  /// Generates a new [SignatureWand] that uses the given seed bytes.
  ///
  /// This will throw [UnsupportedError] if the algorithm does not support
  /// seeds for private key generation.
  Future<SignatureWand> newSignatureWandFromSeed(List<int> seed) async {
    final keyPair = await newKeyPairFromSeed(seed);
    return newSignatureWandFromKeyPair(keyPair);
  }

  /// Signs bytes.
  ///
  /// ## Example
  /// In this example, we use [Ed25519]:
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final signedMessage = [1,2,3];
  ///
  ///   final ed25519 = Ed25519();
  ///   final keyPair = await ed25519.newKeyPair();
  ///   final signature = await ed25519.sign(
  ///     signedMessage,
  ///     keyPair: keyPair,
  ///   );
  ///
  ///   // ...
  ///
  ///   final isRealSignature = await ed25519.verify(
  ///     signedMessage,
  ///     signature: signature,
  ///   );
  ///
  ///   print('Signature verification result: $isRealSignature');
  /// }
  /// ```
  Future<Signature> sign(List<int> message, {required KeyPair keyPair});

  /// Signs a string.
  ///
  /// The string is converted to bytes using [utf8] codec.
  ///
  /// ## Example
  /// In this example, we use [Ed25519]:
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final signedMessage = 'Hello, world!';
  ///
  ///   final ed25519 = Ed25519();
  ///   final keyPair = await ed25519.newKeyPair();
  ///   final signature = await ed25519.signString(
  ///     signedMessage,
  ///     keyPair: keyPair,
  ///   );
  ///
  ///   // ...
  ///
  ///   final isRealSignature = await ed25519.verifyString(
  ///     signedMessage,
  ///     signature: signature,
  ///   );
  ///
  ///   print('Signature verification result: $isRealSignature');
  /// }
  /// ```
  Future<Signature> signString(String message, {required KeyPair keyPair}) {
    return sign(
      utf8.encode(message),
      keyPair: keyPair,
    );
  }

  /// Verifies whether bytes was signed with [signature].
  ///
  /// ## Example
  /// In this example, we use [Ed25519]:
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final signedMessage = [1,2,3];
  ///
  ///   final ed25519 = Ed25519();
  ///   final keyPair = await ed25519.newKeyPair();
  ///   final signature = await ed25519.sign(
  ///     signedMessage,
  ///     keyPair: keyPair,
  ///   );
  ///
  ///   // ...
  ///
  ///   final isRealSignature = await ed25519.verify(
  ///     signedMessage,
  ///     signature: signature,
  ///   );
  ///
  ///   print('Signature verification result: $isRealSignature');
  /// }
  /// ```
  Future<bool> verify(List<int> message, {required Signature signature});

  /// Verifies whether a string was signed with [signature].
  ///
  /// The string is converted to bytes using [utf8] codec.
  ///
  /// ## Example
  /// In this example, we use [Ed25519]:
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final signedMessage = 'Hello, world!';
  ///
  ///   final ed25519 = Ed25519();
  ///   final keyPair = await ed25519.newKeyPair();
  ///   final signature = await ed25519.signString(
  ///     signedMessage,
  ///     keyPair: keyPair,
  ///   );
  ///
  ///   // ...
  ///
  ///   final isRealSignature = await ed25519.verifyString(
  ///     signedMessage,
  ///     signature: signature,
  ///   );
  ///
  ///   print('Signature verification result: $isRealSignature');
  /// }
  /// ```
  Future<bool> verifyString(String message, {required Signature signature}) {
    return verify(
      utf8.encode(message),
      signature: signature,
    );
  }
}

class _SignatureWand extends SignatureWand {
  final SignatureAlgorithm signatureAlgorithm;
  final KeyPair _keyPair;

  _SignatureWand(
    this.signatureAlgorithm,
    this._keyPair,
  ) : super.constructor();

  @override
  Future<void> destroy() async {
    await super.destroy();
    _keyPair.destroy();
  }

  @override
  Future<PublicKey> extractPublicKeyUsedForSignatures() {
    return _keyPair.extractPublicKey();
  }

  @override
  Future<Signature> sign(List<int> message) {
    if (hasBeenDestroyed) {
      throw StateError('destroy() has been called');
    }
    return signatureAlgorithm.sign(
      message,
      keyPair: _keyPair,
    );
  }
}
