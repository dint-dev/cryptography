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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/src/utils.dart';

/// Output of encrypting bytes with a [Cipher].
///
/// This class holds:
///  * [nonce] ("initialization vector", "IV", "salt")
///  * [cipherText]
///  * [mac] (message authentication code)
///
/// ## Concatenating fields
///
/// You can use [concatenation] and [SecretBox.fromConcatenation] to concatenate
/// the fields into a single byte array:
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// void main() async {
///   final aesGcm = AesGcm.with256bits();
///   final secretKey = await aesGcm.newSecretKey();
///   final secretBox = await aesGcm.encrypt(
///     [1,2,3],
///     secretKey: secretKey,
///   );
///
///   // Returns nonce + cipherText + mac
///   final bytes = secretBox.concatenation();
///   print('Encrypted: $bytes');
///
///   // Splits the bytes into nonce, ciphertext, and MAC.
///   final newSecretBox = SecretBox.fromConcatenation(
///     bytes,
///     nonceLength: aesGcm.nonceLength,
///     macLength: aesGcm.macAlgorithm.macLength,
///     copy: false, // Don't copy the bytes unless necessary.
///   );
///
///   final clearText = await aesGcm.decrypt(
///     newSecretBox,
///     secretKey: secretKey,
///   );
///   print('Decrypted: $clearText');
/// }
/// ```
class SecretBox {
  /// Encrypted data.
  final List<int> cipherText;

  /// Message authentication code (MAC) calculated by the encrypting party.
  final Mac mac;

  /// Nonce ("initialization vector", "IV", "salt") is a non-secret sequence of
  /// bytes required by most [Cipher] algorithms.
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
      throw SecretBoxAuthenticationError();
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
  ///
  /// If [copy] is `true`, the [cipherText], [nonce] and [mac] are copied from
  /// the data. If [copy] is `false` and [data] is [Uint8List],
  /// [Uint8List.view] will be used.
  static SecretBox fromConcatenation(
    List<int> data, {
    required int nonceLength,
    required int macLength,
    bool copy = true,
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
      final nonce = Uint8List.view(
        data.buffer,
        data.offsetInBytes,
        nonceLength,
      );
      final cipherText = Uint8List.view(
        data.buffer,
        data.offsetInBytes + nonceLength,
        data.length - nonceLength - macLength,
      );
      final macBytes = Uint8List.view(
        data.buffer,
        data.offsetInBytes + data.lengthInBytes - macLength,
        macLength,
      );
      if (copy) {
        return SecretBox(
          Uint8List.fromList(cipherText),
          nonce: Uint8List.fromList(nonce),
          mac: Mac(Uint8List.fromList(macBytes)),
        );
      }
      return SecretBox(
        cipherText,
        nonce: nonce,
        mac: Mac(macBytes),
      );
    } else {
      return fromConcatenation(
        Uint8List.fromList(data),
        nonceLength: nonceLength,
        macLength: macLength,
        copy: false,
      );
    }
  }
}

/// Thrown by [Cipher] if invalid padding is found during [SecretBox]
/// decryption.
class SecretBoxPaddingError implements Exception {
  final String message;

  SecretBoxPaddingError({String? message})
      : message = message ?? 'Incorrect padding';

  @override
  String toString() => '$SecretBoxPaddingError(message: "$message")';
}
