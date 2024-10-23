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

import '../../cryptography_plus.dart';

/// An opaque object that has some key pair and support for [sign].
///
/// You can extract the [PublicKey] with [extractPublicKeyUsedForSignatures].
/// The private key is not extractable.
///
/// ## Example
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final ed25519 = Ed25519();
///   final wand = await ed25519.newSignatureWand();
///   final signature = await wand.sign(someData);
/// }
/// ```
abstract class SignatureWand extends Wand {
  /// Constructor for subclasses.
  SignatureWand.constructor();

  /// Extracts the public key that is used for signatures.
  Future<PublicKey> extractPublicKeyUsedForSignatures();

  /// Signs bytes.
  ///
  /// ## Example
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final ed25519 = Ed25519();
  ///   final aliceWand = await ed25519.newKeyExchangeWand();
  ///   final signedMessage = [1,2,3];
  ///   final signature = await aliceWand.sign(signedMessage);
  ///   print('Signature: ${signature.bytes}');
  ///   print('Public key: ${signature.publicKey}');
  /// }
  /// ```
  Future<Signature> sign(List<int> message);

  /// Signs a string.
  ///
  /// The string is converted to bytes using [utf8] codec.
  ///
  /// ## Example
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final signedMessage = 'Hello, world!';
  ///
  ///   final ed25519 = Ed25519();
  ///   final wand = await ed25519.newKeyExchangeWand();
  ///   final signature = await wand.signString(signedMessage);
  ///
  ///   print('Signature: ${signature.bytes}');
  ///   print('Public key: ${signature.publicKey}');
  /// }
  /// ```
  Future<Signature> signString(String message) async {
    final bytes = utf8.encode(message);
    final signature = await sign(bytes);
    return signature;
  }
}
