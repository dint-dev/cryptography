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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/cryptography/authenticated_cipher.dart';
import 'package:cryptography/utils.dart';
import 'package:meta/meta.dart';

/// _Chacha20_ ([https://tools.ietf.org/html/rfc7539](RFC 7539) cipher.
///
/// Remember that:
///   * You must not use the same key/nonce combination twice.
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = chacha20Poly1305Aead;
///
///   // Generate a random 256-bit secret key
///   final secretKey = await algorithm.newSecretKey();
///
///   // Generate a random 96-bit nonce.
///   final nonce = algorithm.newNonce();
///
///   // Encrypt.
///   final authenticatedCipherText = await algorithm.encrypt(
///     [1, 2, 3],
///     secretKey: secretKey,
///     nonce: nonce, // The same secretKey/nonce combination should not be used twice
///     aad: const <int>[], // You can authenticate additional data here
///   );
///   print('Ciphertext: ${authenticatedCipherText.cipherText}');
///   print('MAC: ${authenticatedCipherText.mac}');
///
///   // Decrypt.
///   //
///   // If the message authentication code is incorrect,
///   // the method will return null.
///   //
///   final decrypted = await algorithm.decrypt(
///     authenticatedCipherText,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const Chacha20Poly1305Aead chacha20Poly1305Aead = Chacha20Poly1305Aead._();

class Chacha20Poly1305Aead extends AuthenticatedCipher {
  static final _footer = ByteData(16);
  static final _footerUint8List = Uint8List.view(_footer.buffer);

  const Chacha20Poly1305Aead._();

  @override
  Cipher get cipher => chacha20;

  @override
  MacAlgorithm get macAlgorithm => poly1305;

  @override
  Future<Uint8List> decrypt(
    AuthenticatedCipherText input, {
    List<int> aad,
    @required SecretKey secretKey,
    @required Nonce nonce,
  }) async {
    // Calculate MAC
    final expectedMac = await _calculateMac(
      input.cipherText,
      aad: aad,
      secretKey: secretKey,
      nonce: nonce,
    );

    // Verify MAC
    if (input.mac != expectedMac) {
      return null;
    }

    return chacha20.decrypt(
      input.cipherText,
      secretKey: secretKey,
      nonce: nonce,
      offset: 64, // Block counter = 1
    );
  }

  @override
  Future<AuthenticatedCipherText> encrypt(
    List<int> input, {
    List<int> aad,
    @required SecretKey secretKey,
    @required Nonce nonce,
  }) async {
    final cipherText = await cipher.encrypt(
      input,
      secretKey: secretKey,
      nonce: nonce,
      offset: 64, // Block counter = 1
    );

    final mac = await _calculateMac(
      cipherText,
      aad: aad,
      secretKey: secretKey,
      nonce: nonce,
    );

    return AuthenticatedCipherText(
      cipherText: cipherText,
      mac: mac,
    );
  }

  /// Calculates MAC.
  Future<Mac> _calculateMac(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    @required List<int> aad,
  }) async {
    final secretKeyForPoly1305 = await poly1305SecretKeyFromChacha20(
      secretKey,
      nonce: nonce,
    );
    final sink = poly1305.newSink(secretKey: secretKeyForPoly1305);
    var length = 0;

    // Add Additional Authenticated Data (AAD)
    final aadLength = aad == null ? 0 : aad.length;
    if (aadLength != 0) {
      sink.add(aad);
      length += aad.length;

      final rem = length % 16;
      if (rem != 0) {
        // Add padding
        final paddingLength = 16 - rem;
        sink.add(_footerUint8List.sublist(0, paddingLength));
        length += paddingLength;
      }
    }

    // Add cipherText
    sink.add(cipherText);
    length += cipherText.length;
    final rem = length % 16;
    if (rem != 0) {
      // Add padding
      final paddingLength = 16 - rem;
      sink.add(_footerUint8List.sublist(0, paddingLength));
      length += paddingLength;
    }

    // Add 16-byte footer
    final footerByteData = _footer;
    footerByteData.setUint32(
      0,
      uint32mask & aadLength,
      Endian.little,
    );
    footerByteData.setUint32(
      4,
      aadLength >> 32,
      Endian.little,
    );
    footerByteData.setUint32(
      8,
      uint32mask & cipherText.length,
      Endian.little,
    );
    footerByteData.setUint32(
      12,
      cipherText.length >> 32,
      Endian.little,
    );
    sink.add(_footerUint8List);

    // Reset the static buffer for the footer
    footerByteData.setUint32(0, 0);
    footerByteData.setUint32(4, 0);
    footerByteData.setUint32(8, 0);
    footerByteData.setUint32(12, 0);

    // Return MAC
    return sink.close();
  }
}
