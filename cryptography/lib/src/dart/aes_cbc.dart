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

import 'aes_impl.dart';

/// [AesCbc] implemented in pure Dart.
class DartAesCbc extends AesCbc with DartAesMixin {
  @override
  final MacAlgorithm macAlgorithm;

  @override
  final int secretKeyLength;

  const DartAesCbc({required this.macAlgorithm, this.secretKeyLength = 32})
      : assert(secretKeyLength == 16 ||
            secretKeyLength == 24 ||
            secretKeyLength == 32),
        super.constructor();

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    // Validate arguments
    final secretKeyData = await secretKey.extract();
    final actualSecretKeyLength = secretKeyData.bytes.length;
    final expectedSecretKeyLength = secretKeyLength;
    if (actualSecretKeyLength != expectedSecretKeyLength) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Expected $secretKeyLength bytes, got $actualSecretKeyLength bytes',
      );
    }
    final nonceLength = secretBox.nonce.length;
    if (nonceLength != 16) {
      throw ArgumentError.value(
        secretBox,
        'secretBox',
        'Expected nonce with 16 bytes, got $nonceLength bytes',
      );
    }
    if (keyStreamIndex < 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
      );
    }

    // Authenticate
    await secretBox.checkMac(
      macAlgorithm: macAlgorithm,
      secretKey: secretKeyData,
      aad: aad,
    );

    final secretKeyBytes = secretKeyData.bytes;
    final cipherText = secretBox.cipherText;
    if (cipherText.length % 16 != 0) {
      throw ArgumentError.value(
        secretBox,
        'secretBox',
        'Invalid cipherText length: ${cipherText.length}',
      );
    }

    // Expand key
    final preparedKey =
        aesExpandKeyForDecrypting(SecretKeyData(secretKeyBytes));

    // Construct output
    final outputAsUint32List = Uint32List(cipherText.length ~/ 16 * 4);
    final outputAsUint8List = Uint8List.view(outputAsUint32List.buffer);
    outputAsUint8List.setAll(0, cipherText);
    assert(outputAsUint8List.length == cipherText.length);

    // Current block
    var e0 = 0;
    var e1 = 0;
    var e2 = 0;
    var e3 = 0;

    for (var i = 0; i < outputAsUint32List.length; i += 4) {
      // Memorize previous encrypted block
      final p0 = e0;
      final p1 = e1;
      final p2 = e2;
      final p3 = e3;

      // Memorize encrypted block
      e0 = outputAsUint32List[i];
      e1 = outputAsUint32List[i + 1];
      e2 = outputAsUint32List[i + 2];
      e3 = outputAsUint32List[i + 3];

      // Block function
      aesDecryptBlock(
        outputAsUint32List,
        i,
        outputAsUint32List,
        i,
        preparedKey,
      );

      if (i == 0) {
        // block ^= nonce
        final nonceBytes = secretBox.nonce;
        for (var i = 0; i < nonceBytes.length; i++) {
          outputAsUint8List[i] ^= nonceBytes[i];
        }
      } else {
        // block ^= previous_block
        outputAsUint32List[i] ^= p0;
        outputAsUint32List[i + 1] ^= p1;
        outputAsUint32List[i + 2] ^= p2;
        outputAsUint32List[i + 3] ^= p3;
      }
    }

    // PKCS7 padding:
    // The last byte has padding length.
    final paddingLength = outputAsUint8List.last;
    if (paddingLength == 0 || paddingLength > 16) {
      throw StateError(
        'The decrypted bytes have invalid PKCS7 padding length in the end: $paddingLength',
      );
    }

    // Check that all padding bytes are correct PKCS7 padding bytes.
    for (var i = outputAsUint8List.length - paddingLength;
        i < outputAsUint8List.length;
        i++) {
      if (outputAsUint8List[i] != paddingLength) {
        throw StateError('The decrypted bytes are missing padding');
      }
    }
    if (paddingLength == 0) {
      return outputAsUint8List;
    }
    return Uint8List.view(
      outputAsUint32List.buffer,
      outputAsUint32List.offsetInBytes,
      outputAsUint32List.lengthInBytes - paddingLength,
    );
  }

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    // Check parameters
    final secretKeyData = await secretKey.extract();
    final actualSecretKeyLength = secretKeyData.bytes.length;
    final expectedSecretKeyLength = secretKeyLength;
    if (actualSecretKeyLength != expectedSecretKeyLength) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Expected $secretKeyLength bytes, got $actualSecretKeyLength bytes',
      );
    }
    nonce ??= newNonce();
    if (nonceLength != 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Expected nonce with 16 bytes, got $nonceLength bytes',
      );
    }
    if (keyStreamIndex < 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
      );
    }

    // Expand key
    final expandedKey = aesExpandKeyForEncrypting(secretKeyData);

    // Construct Uint32List list for the output
    final paddingLength = 16 - clearText.length % 16;
    final cipherTextBlocks = Uint32List(
      (clearText.length + paddingLength) ~/ 16 * 4,
    );
    final cipherTextBytes = Uint8List.view(cipherTextBlocks.buffer);

    // Fill output with input + PKCS7 padding
    cipherTextBytes.setRange(0, clearText.length, clearText);
    cipherTextBytes.fillRange(
      clearText.length,
      cipherTextBytes.lengthInBytes,
      paddingLength,
    );
    if (Endian.host == Endian.big) {
      final outputByteData = ByteData.view(cipherTextBytes.buffer);
      for (var i = 0; i < cipherTextBytes.length; i += 4) {
        cipherTextBytes[i] = outputByteData.getUint32(i, Endian.big);
      }
    }

    for (var i = 0; i < cipherTextBlocks.length; i += 4) {
      if (i == 0) {
        // block ^= nonce
        final nonceBytes = nonce;
        for (var i = 0; i < nonceBytes.length; i++) {
          cipherTextBytes[i] ^= nonceBytes[i];
        }
      } else {
        // block ^= previous_block
        for (var j = 0; j < 4; j++) {
          cipherTextBlocks[i + j] ^= cipherTextBlocks[i + j - 4];
        }
      }

      // Block function
      aesEncryptBlock(
        cipherTextBlocks,
        i,
        cipherTextBlocks,
        i,
        expandedKey,
      );
    }
    final mac = await macAlgorithm.calculateMac(
      cipherTextBytes,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    return SecretBox(cipherTextBytes, nonce: nonce, mac: mac);
  }
}
