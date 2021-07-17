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

import '../utils.dart';
import 'aes_impl.dart';

/// [AesCtr] implemented in pure Dart.
class DartAesCtr extends AesCtr with DartAesMixin {
  @override
  final MacAlgorithm macAlgorithm;

  @override
  final int counterBits;

  @override
  final int secretKeyLength;

  const DartAesCtr({
    required this.macAlgorithm,
    this.secretKeyLength = 32,
    this.counterBits = 64,
  })  : assert(secretKeyLength == 16 ||
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

    return _perform(
      secretBox.cipherText,
      secretKeyData: secretKeyData,
      nonce: secretBox.nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
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
    nonce ??= newNonce();
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
    final cipherText = _perform(
      clearText,
      secretKeyData: secretKeyData,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
    final mac = await macAlgorithm.calculateMac(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    return SecretBox(cipherText, nonce: nonce, mac: mac);
  }

  Uint8List _perform(
    List<int> data, {
    required SecretKeyData secretKeyData,
    required List<int> nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) {
    // Create 16 byte nonce from a possibly shorter nonce.
    final stateBytes = Uint8List(16);
    stateBytes.setAll(0, nonce);
    final state = Uint32List.view(stateBytes.buffer);

    // Append key stream index
    if (keyStreamIndex != 0) {
      bytesIncrementBigEndian(stateBytes, keyStreamIndex ~/ 16);
    }

    // Allocate output bytes
    final keyStream = Uint32List(
      (keyStreamIndex % 16 + data.length + 15) ~/ 16 * 4,
    );

    // Expand AES key
    final preparedKey = aesExpandKeyForEncrypting(secretKeyData);

    // For each block
    for (var i = 0; i < keyStream.length; i += 4) {
      // Encrypt nonce with AES
      aesEncryptBlock(keyStream, i, state, 0, preparedKey);

      // Increment nonce.
      bytesIncrementBigEndian(stateBytes, 1);
    }

    // result = keyStream[start,end] ^ data
    final result = Uint8List.view(
      keyStream.buffer,
      keyStream.offsetInBytes + keyStreamIndex % 16,
      data.length,
    );
    for (var i = 0; i < data.length; i++) {
      result[i] ^= data[i];
    }
    return result;
  }
}
