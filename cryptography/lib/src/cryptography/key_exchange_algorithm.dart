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

import 'package:cryptography_plus/cryptography_plus.dart';

/// Abstract superclass for key exchange algorithms.
///
/// A key exchange algorithm must support [newKeyPair()] and
/// [sharedSecretKey()].
///
/// ## Available algorithms
///   * [Ecdh.p256]
///   * [Ecdh.p384]
///   * [Ecdh.p521]
///   * [X25519]
///
/// ## Example
/// In this example, we use [X25519]:
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   // Generate a key pair for Alice
///   final algorithm = X25519();
///   final aliceKeyPair = await algorithm.newKeyPair();
///
///   // Generate a key pair for Bob.
///   //
///   // In a real application, we will receive or know Bob's public key
///   // somehow.
///   final bobKeyPair = await algorithm.newKeyPair();
///   final bobPublicKey = await bobKeyPair.extractPublicKey();
///
///   // We can now calculate a shared secret.
///   final sharedSecret = await algorithm.sharedSecretKey(
///     keyPair: aliceKeyPair,
///     remotePublicKey: bobPublicKey,
///   );
///   final sharedSecretBytes = await sharedSecret.extractBytes();
///   print('Shared secret: $sharedSecretBytes');
/// }
///```
abstract class KeyExchangeAlgorithm {
  const KeyExchangeAlgorithm();

  KeyPairType get keyPairType;

  /// Returns a new [KeyExchangeWand] that has a random [KeyPair].
  Future<KeyExchangeWand> newKeyExchangeWand() async {
    final keyPair = await newKeyPair();
    return newKeyExchangeWandFromKeyPair(keyPair);
  }

  /// Returns a new [KeyExchangeWand] that uses the given [KeyPair].
  Future<KeyExchangeWand> newKeyExchangeWandFromKeyPair(KeyPair keyPair) async {
    return _KeyExchangeWand(this, keyPair);
  }

  /// Generates a new [KeyPair] that can be used with this algorithm.
  ///
  /// ## Example
  /// In this example, we use [X25519]:
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final algorithm = X25519();
  ///   final keyPair = await algorithm.newKeyPair();
  /// }
  ///```
  Future<KeyPair> newKeyPair();

  /// Generates a key pair from the seed.
  ///
  /// This will throw [UnsupportedError] if the algorithm does not support
  /// seeds for private key generation.
  ///
  /// ## Example
  /// In this example, we use [X25519]:
  /// ```dart
  /// import 'dart:convert';
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   // X25519 seed is any 32 bytes.
  ///   // We can use SHA256, which computes a 32-byte hash from any input.
  ///   final seed = utf8.encode('example');
  ///   final seedWith32Bytes = (await Sha256().hash(seed)).bytes;
  ///
  ///   final algorithm = X25519();
  ///   final keyPair = await algorithm.newKeyPairFromSeed(seedWith32Bytes);
  /// }
  ///```
  Future<KeyPair> newKeyPairFromSeed(List<int> seed) {
    throw UnsupportedError(
      'newKeyPairFromSeed() is unsupported by this algorithm',
    );
  }

  /// Calculates a shared [SecretKey].
  ///
  /// ## Example
  /// In this example, we use [X25519]:
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final algorithm = X25519();
  ///
  ///   // We need the private key pair of Alice.
  ///   final aliceKeyPair = await algorithm.newKeyPair();
  ///
  ///   // We need only public key of Bob.
  ///   final bobKeyPair = await algorithm.newKeyPair();
  ///   final bobPublicKey = await bobKeyPair.extractPublicKey();
  ///
  ///   // We can now calculate a 32-byte shared secret key.
  ///   final sharedSecretKey = await algorithm.sharedSecretKey(
  ///     keyPair: aliceKeyPair,
  ///     remotePublicKey: bobPublicKey,
  ///   );
  /// }
  /// ```
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  });
}

class _KeyExchangeWand extends KeyExchangeWand {
  final KeyExchangeAlgorithm keyExchangeAlgorithm;
  final KeyPair _keyPair;

  _KeyExchangeWand(
    this.keyExchangeAlgorithm,
    this._keyPair,
  ) : super.constructor();

  @override
  Future<void> destroy() async {
    await super.destroy();
    _keyPair.destroy();
  }

  @override
  Future<PublicKey> extractPublicKey() => _keyPair.extractPublicKey();

  @override
  Future<SecretKey> sharedSecretKey({required PublicKey remotePublicKey}) {
    if (hasBeenDestroyed) {
      throw StateError('destroy() has been called');
    }
    return keyExchangeAlgorithm.sharedSecretKey(
      keyPair: _keyPair,
      remotePublicKey: remotePublicKey,
    );
  }
}
