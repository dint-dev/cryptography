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

import 'dart:async';

import 'package:cryptography_plus/cryptography_plus.dart';

/// A mixin for pure Dart implementations of [KeyExchangeAlgorithm].
mixin DartKeyExchangeAlgorithmMixin implements KeyExchangeAlgorithm {
  @override
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  }) async {
    final keyPairData = await keyPair.extract();
    return sharedSecretSync(
      keyPairData: keyPairData,
      remotePublicKey: remotePublicKey,
    );
  }

  /// Computes shared secret synchronously (unlike [sharedSecretKey]).
  ///
  /// ## Example
  /// In this example, we use [DartX25519] class:
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// void main() async {
  ///   final algorithm = DartX25519();
  ///
  ///   // We need the private key pair of Alice.
  ///   final aliceKeyPair = algorithm.newKeyPairSync();
  ///
  ///   // We need only public key of Bob.
  ///   final bobKeyPair = algorithm.newKeyPairSync();
  ///   final bobPublicKey = bobKeyPair.publicKey;
  ///
  ///   // We can now calculate a 32-byte shared secret key.
  ///   final sharedSecretKey = algorithm.sharedSecretKeySync(
  ///     keyPair: aliceKeyPair,
  ///     remotePublicKey: bobPublicKey,
  ///   );
  /// }
  /// ```
  SecretKey sharedSecretSync({
    required KeyPairData keyPairData,
    required PublicKey remotePublicKey,
  });
}
