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

import '../../cryptography_plus.dart';

/// An opaque object that has some key pair and support for [sharedSecretKey].
///
/// You can extract the [PublicKey] with [extractPublicKey].
/// The private key is not extractable.
///
/// ## Example
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final x25519 = X25519();
///   final aliceWand = await x25519.newKeyExchangeWand();
///   final bobPublicKey = await (await x25519.newKeyPair()).extractPublicKey();
///   final secretKey = await aliceWand.sharedSecretKey(
///     remotePublicKey: bobPublicKey,
///   );
/// }
/// ```
abstract class KeyExchangeWand extends Wand {
  /// Constructor for subclasses.
  KeyExchangeWand.constructor();

  /// Extracts the public key is used for key exchanges.
  Future<PublicKey> extractPublicKey();

  /// Computes the shared secret key that this and the other party can compute
  /// using public keys known to each other.
  ///
  /// ## Example
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final x25519 = X25519();
  ///
  ///   // Alice has her private key.
  ///   final aliceWand = await x25519.newKeyExchangeWand();
  ///
  ///   // Bob gives his public key to Alice.
  ///   final bobPublicKey = await (await x25519.newKeyPair()).extractPublicKey();
  ///
  ///   // Alice can now compute a shared secret key.
  ///   // If Bob does the same, he will get the same key.
  ///   // Other parties cannot compute the same key.
  ///   final secretKey = await aliceWand.sharedSecretKey(
  ///     remotePublicKey: bobPublicKey,
  ///   );
  /// }
  /// ```
  Future<SecretKey> sharedSecretKey({
    required PublicKey remotePublicKey,
  });
}
