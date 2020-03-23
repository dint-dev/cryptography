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

import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

/// A combination of [Cipher] and [MacAlgorithm].
///
/// The output of encryption (and input of decryption) is
/// [AuthenticatedCipherText].
///
/// Examples:
///   * [chacha20Poly1305Aead]
///
/// ```
/// const chacha20HmacSha256 = AuthenticatedCipher.from(
///   cipher: chacha20,
///   macAlgorithm: Hmac(sha256),
/// );
abstract class AuthenticatedCipher {
  const AuthenticatedCipher();

  /// Constructs an authenticated cipher.
  ///
  /// The MAC algorithm is applied to the ciphertext, not plaintext.
  const factory AuthenticatedCipher.from({
    @required Cipher cipher,
    @required MacAlgorithm macAlgorithm,
  }) = _AuthenticatedCipher;

  /// Cipher used for encryption/decryption.
  Cipher get cipher;

  /// Message authentication code (MAC) algorithm.
  MacAlgorithm get macAlgorithm;

  /// Whether the algorithm supports Associated Authenticated Data (AAD).
  ///
  /// Default is false.
  bool get supportsAad => false;

  /// Decrypts the message. If MAC is incorrect, returns null.
  ///
  /// Some algorithms (such as [chacha20Poly1305Aead]) support authenticating
  /// optional Associated Authenticated Data (AAD) at the same time.
  Future<Uint8List> decrypt(
    AuthenticatedCipherText input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
  });

  /// Encrypts the message and calculates authentication code.
  ///
  /// Some algorithms (such as [chacha20Poly1305Aead]) support authenticating
  /// optional Associated Authenticated Data (AAD) at the same time.
  Future<AuthenticatedCipherText> encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
  });
}

/// A ciphertext and a Message Authentication Code (MAC).
class AuthenticatedCipherText {
  final List<int> cipherText;
  final Mac mac;

  const AuthenticatedCipherText({@required this.cipherText, @required this.mac})
      : assert(cipherText != null),
        assert(mac != null);

  @override
  int get hashCode => mac.hashCode;

  @override
  bool operator ==(other) =>
      other is AuthenticatedCipherText &&
      mac == other.mac &&
      const ListEquality<int>().equals(cipherText, other.cipherText);

  /// Returns concatenation of ciphertext and MAC.
  Uint8List toBytes() {
    // Allocate bytes
    final cipherText = this.cipherText;
    final bytes = mac.bytes;
    final result = Uint8List(cipherText.length + bytes.length);

    // Write cipherText
    for (var i = 0; i < cipherText.length; i++) {
      result[i] = cipherText[i];
    }

    // Write MAC
    var resultIndex = cipherText.length;
    for (var i = 0; i < bytes.length; i++) {
      result[resultIndex] = bytes[i];
      resultIndex++;
    }
    return result;
  }
}

class _AuthenticatedCipher extends AuthenticatedCipher {
  @override
  final Cipher cipher;
  @override
  final MacAlgorithm macAlgorithm;

  const _AuthenticatedCipher({
    this.cipher,
    this.macAlgorithm,
  });

  @override
  Future<Uint8List> decrypt(
    AuthenticatedCipherText input, {
    @required SecretKey secretKey,
    List<int> aad,
    Nonce nonce,
  }) async {
    if (aad != null) {
      throw ArgumentError.value(
        aad,
        'aad',
        '$this does not support associated authenticated data.',
      );
    }
    final mac = await macAlgorithm.calculateMac(
      input.cipherText,
      secretKey: secretKey,
    );
    if (mac != input.mac) {
      return null;
    }
    return cipher.decrypt(
      input.cipherText,
      secretKey: secretKey,
      nonce: nonce,
    );
  }

  @override
  Future<AuthenticatedCipherText> encrypt(
    List<int> input, {
    List<int> aad,
    SecretKey secretKey,
    Nonce nonce,
  }) async {
    if (aad != null) {
      throw ArgumentError.value(
        aad,
        'aad',
        '$this does not support associated authenticated data.',
      );
    }
    final cipherText = await cipher.encrypt(
      input,
      secretKey: secretKey,
      nonce: nonce,
    );
    final mac = await macAlgorithm.calculateMac(
      cipherText,
      secretKey: secretKey,
    );
    return AuthenticatedCipherText(
      cipherText: cipherText,
      mac: mac,
    );
  }

  @override
  String toString() {
    return 'AuthenticatedCipher.from(cipher:$cipher, macAlgorithm:$macAlgorithm)';
  }
}
