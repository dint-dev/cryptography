// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   final keyPair = x25519.keyPairGenerator.generateSync();
///   final sharedKey = await ecdsaP256.sign([1,2,3], keyPair);
///
///   // Anyone can verify the signature
///   final isVerified = await ecdsaP256.verify([1,2,3], signature);
/// }
/// ```
abstract class KeyExchangeAlgorithm {
  const KeyExchangeAlgorithm();

  /// A keypair generator for this algorithm.
  KeyPairGenerator get keyPairGenerator;

  /// Name of this algorithm.
  String get name;

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
