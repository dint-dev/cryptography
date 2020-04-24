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
import 'package:cryptography/utils.dart';
import 'package:meta/meta.dart';

/// _ChaCha20_ ([https://tools.ietf.org/html/rfc7539](RFC 7539) cipher.
///
/// Remember that:
///   * You must not use the same key/nonce combination twice.
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   // Generate a random 256-bit secret key
///   final secretKey = SecretKey.randomBytes(32);
///
///   // Generate a random 96-bit nonce.
///   final nonce = Nonce.randomBytes(12);
///
///   // Encrypt
///   final clearText = <int>[1, 2, 3];
///   final encrypted = await chacha20Poly1305Aead.encrypt(
///     clearText,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   print('Bytes: ${chacha20Poly1305Aead.getDataInCipherText(encrypted)}');
///   print('MAC: ${chacha20Poly1305Aead.getMacInCipherText(encrypted)}');
///
///   // Decrypt.
///   //
///   // If the message authentication code is incorrect,
///   // the method will return null.
///   //
///   final decrypted = await algorithm.decrypt(
///     cipherText,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const CipherWithAppendedMac chacha20Poly1305Aead = Chacha20Poly1305Aead();

/// {@nodoc}
@visibleForTesting
class Chacha20Poly1305Aead extends CipherWithAppendedMac {
  static final _tmpByteData = ByteData(16);
  static final _tmpUint8List = Uint8List.view(_tmpByteData.buffer);

  const Chacha20Poly1305Aead({
    Cipher cipher = chacha20,
    MacAlgorithm macAlgorithm = poly1305,
  }) : super(cipher, macAlgorithm);

  @override
  bool get supportsAad => true;

  @override
  String get name => 'chacha20Poly1305Aead';

  @override
  List<int> encryptSync(
    List<int> clearText, {
    SecretKey secretKey,
    Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    final cipherTextWithoutMac = cipher.encryptSync(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
      aad: null,
      // Block counter 0 is used for Poly1305 key generation
      keyStreamIndex: 64 + keyStreamIndex,
    );
    final mac = calculateMacSync(
      cipherTextWithoutMac,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    final result = Uint8List(cipherTextWithoutMac.length + 16);
    result.setAll(0, cipherTextWithoutMac);
    result.setAll(cipherTextWithoutMac.length, mac.bytes);
    return result;
  }

  @override
  List<int> decryptSync(
    List<int> cipherText, {
    SecretKey secretKey,
    Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    final dataInCipherText = getDataInCipherText(cipherText);
    final calculatedMac = calculateMacSync(
      dataInCipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    final macInCipherText = getMacInCipherText(cipherText);

    if (macInCipherText != calculatedMac) {
      return null;
    }
    return cipher.decryptSync(
      dataInCipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: null,
      // Block counter 0 is used for Poly1305 key generation
      keyStreamIndex: 64 + keyStreamIndex,
    );
  }

  @override
  Mac calculateMacSync(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    @required List<int> aad,
  }) {
    final secretKeyForPoly1305 = poly1305SecretKeyFromChacha20(
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
        sink.add(_tmpUint8List.sublist(0, paddingLength));
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
      sink.add(_tmpUint8List.sublist(0, paddingLength));
      length += paddingLength;
    }

    // Add 16-byte footer.
    // We can't use setUint64() because it's not supported in the browsers.
    final tmpByteData = _tmpByteData;
    tmpByteData.setUint32(
      0,
      uint32mask & aadLength,
      Endian.little,
    );
    tmpByteData.setUint32(
      4,
      aadLength ~/ (uint32mask + 1),
      Endian.little,
    );
    tmpByteData.setUint32(
      8,
      uint32mask & cipherText.length,
      Endian.little,
    );
    tmpByteData.setUint32(
      12,
      cipherText.length ~/ (uint32mask + 1),
      Endian.little,
    );
    sink.add(_tmpUint8List);

    // Reset the static buffer.
    tmpByteData.setUint32(0, 0);
    tmpByteData.setUint32(4, 0);
    tmpByteData.setUint32(8, 0);
    tmpByteData.setUint32(12, 0);

    // Return MAC
    sink.close();
    return sink.mac;
  }
}
