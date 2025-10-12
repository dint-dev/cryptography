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

import '../utils.dart';
import 'aes_impl.dart';

/// [AesCbc] implemented in pure Dart.
///
/// For examples and more information about the algorithm, see documentation for
/// the class [AesCbc].
class DartAesCbc extends AesCbc with DartAesMixin {
  static const int _blockLength = 16;

  @override
  final MacAlgorithm macAlgorithm;

  @override
  final PaddingAlgorithm paddingAlgorithm;

  @override
  final int secretKeyLength;

  const DartAesCbc({
    required this.macAlgorithm,
    this.paddingAlgorithm = PaddingAlgorithm.pkcs7,
    this.secretKeyLength = 32,
    super.random,
  })  : assert(secretKeyLength == 16 ||
            secretKeyLength == 24 ||
            secretKeyLength == 32),
        super.constructor();

  const DartAesCbc.with128bits({
    required MacAlgorithm macAlgorithm,
    PaddingAlgorithm paddingAlgorithm = PaddingAlgorithm.pkcs7,
  }) : this(
          macAlgorithm: macAlgorithm,
          paddingAlgorithm: paddingAlgorithm,
          secretKeyLength: 16,
        );

  const DartAesCbc.with192bits({
    required MacAlgorithm macAlgorithm,
    PaddingAlgorithm paddingAlgorithm = PaddingAlgorithm.pkcs7,
  }) : this(
          macAlgorithm: macAlgorithm,
          paddingAlgorithm: paddingAlgorithm,
          secretKeyLength: 24,
        );

  const DartAesCbc.with256bits({
    required MacAlgorithm macAlgorithm,
    PaddingAlgorithm paddingAlgorithm = PaddingAlgorithm.pkcs7,
  }) : this(
          macAlgorithm: macAlgorithm,
          paddingAlgorithm: paddingAlgorithm,
          secretKeyLength: 32,
        );

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
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
    if (nonceLength != nonceLength) {
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

    // Handle big-endian systems.
    flipUint32ListEndianUnless(outputAsUint32List, Endian.little);

    // Determine length of padding.
    final paddingLength = paddingAlgorithm.getBlockPadding(
      _blockLength,
      outputAsUint8List,
    );
    if (paddingLength < 0) {
      throw SecretBoxPaddingError(
        message: 'Invalid padding. Padding algorithm is $paddingAlgorithm.',
      );
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
    Uint8List? possibleBuffer,
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
    if (nonce.length != nonceLength) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Expected nonce with $nonceLength bytes, got ${nonce.length} bytes',
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
    final paddingLength = paddingAlgorithm.paddingLength(
      _blockLength,
      clearText.length,
    );
    final cipherTextBlocks = Uint32List(
      (clearText.length + paddingLength) ~/ 16 * 4,
    );
    final cipherTextBytes = Uint8List.view(cipherTextBlocks.buffer);

    // Write clear text to buffer
    cipherTextBytes.setRange(0, clearText.length, clearText);

    // Fill output with input + PKCS7 padding
    paddingAlgorithm.setBlockPadding(
      _blockLength,
      cipherTextBytes,
      clearText.length,
    );

    // Handle big-endian systems.
    flipUint32ListEndianUnless(cipherTextBlocks, Endian.little);

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

  @override
  DartAesCbc toSync() => this;
}
