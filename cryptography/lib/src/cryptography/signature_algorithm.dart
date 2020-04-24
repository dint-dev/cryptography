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

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

/// A cryptographic signature. Bytes can be signed with [SignatureAlgorithm].
class Signature {
  /// Signature (without public key).
  final List<int> bytes;

  /// Signer's public key.
  final PublicKey publicKey;

  const Signature(this.bytes, {@required this.publicKey})
      : assert(bytes != null),
        assert(publicKey != null);

  @override
  int get hashCode =>
      const ListEquality<int>().hash(bytes) ^ publicKey.hashCode;

  @override
  bool operator ==(other) =>
      other is Signature &&
      const ListEquality<int>().equals(bytes, other.bytes) &&
      publicKey == other.publicKey;

  @override
  String toString() =>
      'Signature(bytes:[${bytes.join(', ')}], publicKey: [${publicKey.bytes.join(', ')}])';
}

/// Superclass for signature-generating algorithms.
///
/// Examples:
///   * [ecdsaP256Sha256]
///   * [ecdsaP384Sha256]
///   * [ecdsaP521Sha256]
///   * [ed25519]
///
/// An example of using [ed25519]:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   // Sign
///   final keyPair = await ed25519.newKeyPair();
///   final signature = await ed25519.sign(
///     [1,2,3],
///     keyPair,
///   );
///
///   print('Signature bytes: ${signature.bytes}');
///   print('Public key: ${signature.publicKey.bytes}');
///
///   // Anyone can verify the signature
///   final isVerified = await ed25519.verify(
///     [1,2,3],
///     signature,
///   );
/// }
/// ```
abstract class SignatureAlgorithm {
  const SignatureAlgorithm();

  /// A descriptive algorithm name for debugging purposes.
  ///
  /// Examples:
  ///   * "ed25519"
  String get name;

  /// Whether [newKeyPairFromSeed] is supported.
  bool get isSeedSupported => false;

  /// Public key length (in bytes).
  int get publicKeyLength;

  /// Generates a new keypair.
  Future<KeyPair> newKeyPair() => Future<KeyPair>.value(newKeyPairSync());

  /// Generates a new keypair.
  KeyPair newKeyPairSync();

  /// Generates a new keypair from seed. Throws [UnsupportedError] if seeds are
  /// unsupported.
  Future<KeyPair> newKeyPairFromSeed(PrivateKey seed) {
    throw UnsupportedError(
      '$name does not support newKeyPairFromSeed(seed)',
    );
  }

  /// Generates a new keypair from seed. Throws [UnsupportedError] if seeds are
  /// unsupported.
  KeyPair newKeyPairFromSeedSync(PrivateKey seed) {
    throw UnsupportedError(
      '$name does not support newKeyPairFromSeedSync(seed)',
    );
  }

  /// Signs bytes.
  Future<Signature> sign(List<int> input, KeyPair keyPair) {
    return Future<Signature>(() => signSync(input, keyPair));
  }

  /// Signs bytes. Unlike [sign], this method is synchronous. Throws
  /// [UnsupportedError] if the operation can not be performed synchronously.
  Signature signSync(List<int> input, KeyPair keyPair);

  /// Verifies a signature.
  Future<bool> verify(List<int> input, Signature signature) {
    return Future<bool>(() => verifySync(input, signature));
  }

  /// Verifies a signature. Unlike [verify], this method is synchronous. Throws
  /// [UnsupportedError] if the operation can not be performed synchronously.
  bool verifySync(List<int> input, Signature signature);
}
