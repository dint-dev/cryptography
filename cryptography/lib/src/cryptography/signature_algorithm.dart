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

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

/// A cryptographic signature. Bytes can be signed with [SignatureAlgorithm].
class Signature {
  /// Signature bytes.
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
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final keyPair = await ecdsaP256.newKeyPair();
///   final signature = await ecdsaP256.sign([1,2,3], keyPair);
///
///   // Anyone can verify the signature
///   final isVerified = await ecdsaP256.verify([1,2,3], signature);
/// }
/// ```
abstract class SignatureAlgorithm {
  const SignatureAlgorithm();

  /// A keypair generator for this algorithm.
  KeyPairGenerator get keyPairGenerator;

  /// Name of this algorithm.
  String get name;

  /// Signs bytes.
  Future<Signature> sign(List<int> input, KeyPair keyPair) {
    return Future<Signature>(() => signSync(input, keyPair));
  }

  /// Signs bytes synchronously. Throws [UnsupportedError] if the operation can
  /// not be performed synchronously.
  Signature signSync(List<int> input, KeyPair keyPair);

  /// Verifies a signature.
  Future<bool> verify(List<int> input, Signature signature) {
    return Future<bool>(() => verifySync(input, signature));
  }

  /// Verifies a signature synchronously. Throws [UnsupportedError] if the\
  /// operation can not be performed synchronously.
  bool verifySync(List<int> input, Signature signature);
}
