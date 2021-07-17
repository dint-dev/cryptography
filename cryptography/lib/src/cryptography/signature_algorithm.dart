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
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = Ed25519();
///
///   // Generate a new key pair
///   final keyPair = await algorithm.keyGenerator.newKeyPair();
///
///   // Sign
///   final message = <int>[1,2,3];
///   final signature = await algorithm.sign(
///     message,
///     keyPair: keyPair,
///   );
///   print('Signature bytes: ${signature.bytes}');
///   print('Public key: ${signature.publicKey.bytes}');
///
///   // Anyone can verify the signature
///   final isVerified = await ed25519.verify(
///     message,
///     signature: signature,
///   );
///   print('OK signature: $isVerified');
/// }
/// ```
abstract class SignatureAlgorithm {
  const SignatureAlgorithm();

  KeyPairType get keyPairType;

  /// Generates a new [KeyPair] for this algorithm.
  ///
  /// You can pass key generation preferences by specifying `options`.
  Future<KeyPair> newKeyPair();

  Future<KeyPair> newKeyPairFromSeed(List<int> bytes) {
    throw UnsupportedError(
        'newKeyPairFromSeed() is unsupported by this algorithm');
  }

  /// Calculates signature for the message.
  Future<Signature> sign(List<int> message, {required KeyPair keyPair});

  /// Verifies the signature.
  Future<bool> verify(List<int> message, {required Signature signature});
}
