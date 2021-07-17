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
import 'package:cryptography/src/utils.dart';

/// Output of encrypting bytes with a [Cipher].
///
/// This class holds:
///  * [nonce] ("initialization vector", "IV", "salt")
///  * [cipherText]
///  * [mac] (message authentication code)
///
/// ## Concatenating fields
/// When you storing / loading secret boxes, you can use [concatenation] and
/// [fromConcatenation]:
/// ```
/// // Returns nonce + cipherText + mac
/// final bytes = secretBox.concatenation();
///
/// // Splits the bytes into nonce, ciphertext, and MAC.
/// final newSecretBox = SecretBox.fromConcatenation(
///   bytes,
///   nonceLength:16,
///   macLength: 16,
/// );
/// ```
class SecretBox {
  /// Encrypted data.
  final List<int> cipherText;

  /// Message authentication code (MAC) calculated by the encrypting party.
  final Mac mac;

  /// Nonce ("initialization vector", "IV", "salt") is a non-secret sequence of
  /// bytes required by most algorithms.
  final List<int> nonce;

  SecretBox(
    this.cipherText, {
    required this.nonce,
    required this.mac,
  });

  @override
  int get hashCode =>
      mac.hashCode ^
      constantTimeBytesEquality.hash(nonce) ^
      constantTimeBytesEquality.hash(cipherText);

  @override
  bool operator ==(other) =>
      other is SecretBox &&
      mac == other.mac &&
      constantTimeBytesEquality.equals(nonce, other.nonce) &&
      constantTimeBytesEquality.equals(cipherText, other.cipherText);

  /// Checks that the secret box has correct MAC.
  ///
  /// Throws [SecretBoxAuthenticationError] if the MAC is incorrect.
  Future<void> checkMac({
    required MacAlgorithm macAlgorithm,
    required SecretKey secretKey,
    required List<int> aad,
  }) async {
    final correctMac = await macAlgorithm.calculateMac(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    if (correctMac != mac) {
      throw SecretBoxAuthenticationError(secretBox: this);
    }
  }

  /// Returns a concatenation of [nonce], [cipherText] and [mac].
  Uint8List concatenation({bool nonce = true, bool mac = true}) {
    final nonceBytes = this.nonce;
    final cipherText = this.cipherText;
    final macBytes = this.mac.bytes;
    var n = cipherText.length;
    if (nonce) {
      n += nonceBytes.length;
    }
    if (mac) {
      n += macBytes.length;
    }
    final result = Uint8List(n);
    var i = 0;
    if (nonce) {
      result.setAll(i, nonceBytes);
      i += nonceBytes.length;
    }
    result.setAll(i, cipherText);
    i += cipherText.length;
    if (mac) {
      result.setAll(i, macBytes);
    }
    return result;
  }

  @override
  String toString() {
    return 'SecretBox(\n'
        '  [~~${cipherText.length} bytes~~],\n'
        '  nonce: [${nonce.join(',')}],\n'
        '  mac: $mac,\n'
        ')';
  }

  /// Constructs a [SecretBox] from a concatenation of [nonce], [cipherText]
  /// and [mac].
  static SecretBox fromConcatenation(
    List<int> data, {
    required int nonceLength,
    required int macLength,
  }) {
    if (nonceLength < 0) {
      throw ArgumentError.value(nonceLength, 'nonceLength');
    }
    if (macLength < 0) {
      throw ArgumentError.value(macLength, 'macLength');
    }
    if (data.length < nonceLength + macLength) {
      throw ArgumentError.value(
        data,
        'data',
        'Less than minimum length ($nonceLength + $macLength)',
      );
    }
    if (data is Uint8List) {
      final nonce = List<int>.unmodifiable(Uint8List.view(
        data.buffer,
        data.offsetInBytes,
        nonceLength,
      ));
      final cipherText = List<int>.unmodifiable(Uint8List.view(
        data.buffer,
        data.offsetInBytes + nonceLength,
        data.length - nonceLength - macLength,
      ));
      final macBytes = List<int>.unmodifiable(Uint8List.view(
        data.buffer,
        data.offsetInBytes + data.lengthInBytes - macLength,
        macLength,
      ));
      return SecretBox(cipherText, nonce: nonce, mac: Mac(macBytes));
    } else {
      return fromConcatenation(
        Uint8List.fromList(data),
        nonceLength: nonceLength,
        macLength: macLength,
      );
    }
  }
}
