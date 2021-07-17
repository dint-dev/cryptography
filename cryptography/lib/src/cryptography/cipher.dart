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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';

/// A cipher that supports [encrypt()] and [decrypt()].
///
/// ## Available algorithms
///   * [AesCbc]
///   * [AesCtr]
///   * [AesGcm]
///   * [Chacha20]
///   * [Chacha20.poly1305Aead]
///   * [Xchacha20]
///   * [Xchacha20.poly1305Aead]
///
/// ## Example
/// An example of using [AesCtr] and [Hmac]:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   // AES-CTR with 128 bit keys and HMAC-SHA256 authentication.
///   final algorithm = AesCtr.with128bits(
///     macAlgorithm: Hmac.sha256(),
///   );
///   final secretKey = await algorithm.newSecretKey();
///   final nonce = algorithm.newNonce();
///
///   // Encrypt
///   final secretBox = await algorithm.encrypt(
///     message,
///     secretKey: secretKey,
///   );
///   print('Nonce: ${secretBox.nonce}')
///   print('Ciphertext: ${secretBox.cipherText}')
///   print('MAC: ${secretBox.mac.bytes}')
///
///   // Decrypt
///   final clearText = await algorithm.encrypt(
///     secretBox,
///     secretKey: secretKey,
///   );
///   print('Cleartext: $clearText');
/// }
/// ```
abstract class Cipher {
  const Cipher();

  @override
  int get hashCode;

  /// Message authentication code ([MacAlgorithm]) used by the cipher.
  MacAlgorithm get macAlgorithm;

  /// Number of bytes in the nonce ("Initialization Vector", "IV", "salt").
  ///
  /// Method [newNonce] uses this property to generate correct-length nonces.
  ///
  /// Methods [encrypt] and [decrypt] will throw [ArgumentError] if they receive
  /// incorrect-length nonces.
  int get nonceLength;

  /// Number of bytes in the [SecretKey].
  ///
  /// Method [newSecretKey] uses this property to generate correct-length secret
  /// keys.
  ///
  /// Methods [encrypt] and [decrypt] will throw [ArgumentError] if they receive
  /// incorrect-length secret keys.
  int get secretKeyLength;

  @override
  bool operator ==(other);

  /// Decrypts [SecretBox] and returns the bytes.
  ///
  /// Subclasses of `Cipher` do the following:
  ///   1.Authenticates [SecretBox.mac] with [macAlgorithm].
  ///   2.Decrypts [SecretBox.cipherText].
  ///   3.Returns the cleartext.
  ///
  /// The [SecretBox] is authenticated with [SecretBox.checkMac()), which will
  /// throw [SecretBoxAuthenticationError] if the MAC is incorrect.
  ///
  /// You must give a [SecretKey] that has the correct length and type.
  ///
  /// Optional parameter `nonce` (also known as "initialization vector",
  /// "IV", or "salt") is some non-secret unique sequence of bytes.
  /// If you don't define it, the cipher will generate nonce for you.
  ///
  /// Parameter `aad` can be used to pass _Associated Authenticated Data_ (AAD).
  /// If you pass a non-empty list and the underlying cipher doesn't support
  /// AAD, the method will throw [ArgumentError].
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
  });

  /// Encrypts bytes and returns [SecretBox].
  /// Authenticates [SecretBox] with [macAlgorithm], decrypts it, and returns the cleartext.
  ///
  /// You must give a [SecretKey] that has the correct length and type.
  ///
  /// Optional parameter `nonce` (also known as "initialization vector",
  /// "IV", or "salt") is some non-secret unique sequence of bytes.
  /// If you don't define it, the cipher will generate nonce for you.
  ///
  /// Parameter `aad` can be used to pass _Associated Authenticated Data_ (AAD).
  /// If you pass a non-empty list and the underlying cipher doesn't support
  /// AAD, the method will throw [ArgumentError].
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
  });

  /// Generates a new nonce with the correct length ([nonceLength]).
  ///
  /// Uses a cryptographically strong random number generator.
  List<int> newNonce() {
    final bytes = Uint8List(nonceLength);
    fillBytesWithSecureRandom(bytes);
    return bytes;
  }

  /// Generates a new [SecretKey] with the correct length ([secretKeyLength]).
  ///
  /// Uses a cryptographically strong random number generator.
  Future<SecretKey> newSecretKey() {
    final bytes = Uint8List(secretKeyLength);
    fillBytesWithSecureRandom(bytes);
    return newSecretKeyFromBytes(bytes);
  }

  /// Constructs a new [SecretKey] from the bytes.
  ///
  /// Throws [ArgumentError] if the argument length is not [secretKeyLength].
  Future<SecretKey> newSecretKeyFromBytes(List<int> bytes) async {
    if (bytes.length != secretKeyLength) {
      throw ArgumentError('Invalid secret key length');
    }
    return SecretKey(List<int>.unmodifiable(bytes));
  }

  @override
  String toString();
}
