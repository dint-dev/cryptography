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

/// A key exchange algorithm that supports [newKeyPair()] and [sharedSecretKey()].
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
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   // Generate a key pair.
///   final algorithm = X25519();
///   final keyPair = await algorithm.keyGenerator.newKeyPair();
///
///   // Get a public key for our peer.
///   final remoteKeyPair = await algorithm.keyGenerator.newKeyPair();
///   final remotePublicKey = await remoteKeyPair.extractPublicKey();
///
///   // We can now calculate a shared secret.
///   final sharedSecret = await algorithm.sharedSecretKey(
///     keyPair: keyPair,
///     remotePublicKey: remotePublicKey,
///   );
///   final sharedSecretBytes = sharedSecret.extractBytes();
///   print('Shared secret: $sharedSecretBytes');
/// }
///```
abstract class KeyExchangeAlgorithm {
  const KeyExchangeAlgorithm();

  KeyPairType get keyPairType;

  /// Generates a new [KeyPair] for this algorithm.
  ///
  /// You can pass key generation preferences by specifying `options`.
  Future<KeyPair> newKeyPair();

  Future<KeyPair> newKeyPairFromSeed(List<int> bytes) {
    throw UnsupportedError(
      'newKeyPairFromSeed() is unsupported by this algorithm',
    );
  }

  /// Calculates a shared [SecretKey].
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  });
}
