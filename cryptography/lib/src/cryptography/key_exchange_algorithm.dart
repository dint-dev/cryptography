// Copyright 2019-2020 Gohilla Ltd.
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

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

/// Superclass for key exchange algorithms.
///
/// Examples:
///   * [ecdhP256]
///   * [ecdhP384]
///   * [ecdhP521]
///   * [x25519]
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   // Let's generate two keypairs.
///   final localKeyPair = await x25519.newKeyPair();
///   final remoteKeyPair = await x5519.newKeyPair();
///
///   // We can now calculate a shared secret
///   var sharedSecret = await x25519.sharedSecret(
///     localPrivateKey: localKeyPair.privateKey,
///     remotePublicKey: remoteKeyPair.publicKey,
///   );
/// }
///```
abstract class KeyExchangeAlgorithm {
  const KeyExchangeAlgorithm();

  /// Whether [newKeyPairFromSeed] can be used.
  bool get isSeedSupported => false;

  /// A descriptive algorithm name for debugging purposes.
  ///
  /// Examples:
  ///   * "x25519"
  String get name;

  /// Public key length (in bytes).
  int get publicKeyLength;

  /// Generates a random key pair.
  Future<KeyPair> newKeyPair() => Future<KeyPair>.value(newKeyPairSync());

  /// Generates a key pair from the seed.
  /// If the algorithm doesn't support seeds, throws [UnsupportedError].
  Future<KeyPair> newKeyPairFromSeed(PrivateKey seed) {
    return Future<KeyPair>.value(newKeyPairFromSeedSync(seed));
  }

  /// Generates a key pair from the seed.
  /// If the algorithm doesn't support seeds, throws [UnsupportedError].
  ///
  /// If synchronous computation is not supported, throws [UnsupportedError].
  KeyPair newKeyPairFromSeedSync(PrivateKey seed) {
    throw UnsupportedError(
      '$name does not support newKeyPairFromSeedSync(seed)',
    );
  }

  /// Generates a random key pair.
  ///
  /// If synchronous computation is not supported, throws [UnsupportedError].
  KeyPair newKeyPairSync();

  /// Calculates a shared secret.
  ///
  /// Both parameters [localPrivateKey] and [remotePublicKey] must be non-null.
  Future<SecretKey> sharedSecret({
    @required PrivateKey localPrivateKey,
    @required PublicKey remotePublicKey,
  }) {
    return Future<SecretKey>(
      () => sharedSecretSync(
        localPrivateKey: localPrivateKey,
        remotePublicKey: remotePublicKey,
      ),
    );
  }

  /// Calculates a shared secret.
  ///
  /// Both parameters [localPrivateKey] and [remotePublicKey] must be non-null.
  ///
  /// If synchronous computation is not supported, throws [UnsupportedError].
  SecretKey sharedSecretSync({
    @required PrivateKey localPrivateKey,
    @required PublicKey remotePublicKey,
  });
}
