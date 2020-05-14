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
import 'package:meta/meta.dart';

import 'aes_impl_base.dart';

const Cipher dartAesCtr = _AesCtr();

class _AesCtr extends AesCipher {
  const _AesCtr();

  @override
  String get name => 'aesCtr';

  @override
  int get nonceLength => 12;

  @override
  int get secretKeyLength => 32;

  @override
  Set<int> get secretKeyValidLengths => const {16, 24, 32};

  @override
  List<int> decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (aad != null) {
      throw ArgumentError.value(
        aad,
        'aad',
        'Must be null',
      );
    }
    if (nonce.bytes.length > 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be at most 16 bytes',
      );
    }
    if (keyStreamIndex % 16 != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be a multiple of 16',
      );
    }

    // Initialize parameters
    final preparedKey = prepareEncrypt(secretKey.extractSync());

    // Create 16 byte nonce from a possibly shorter nonce.
    var nonceBytes = Uint8List(16);
    nonceBytes.setAll(0, nonce.bytes);
    if (keyStreamIndex != 0) {
      nonceBytes = Nonce(nonceBytes).increment(keyStreamIndex ~/ 16).bytes;
    }

    // Initialize output
    final output = Uint8List.fromList(input);

    // For each block
    for (var i = 0; i < input.length; i += 16) {
      // Encrypt nonce
      aesEncryptBlock(output, i, nonceBytes, 0, preparedKey);
      var blockLength = output.length - i;
      if (blockLength > 16) {
        blockLength = 16;
      }

      // XOR
      xorBlock(output, i, input, i, blockLength);

      // Increment nonce
      nonceBytes = Nonce(nonceBytes).increment().bytes;
    }
    return output;
  }

  @override
  List<int> encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (aad != null) {
      throw ArgumentError.value(
        aad,
        'aad',
        'Must be null',
      );
    }
    if (nonce.bytes.length > 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be at most 16 bytes',
      );
    }
    if (keyStreamIndex % 16 != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be a multiple of 16',
      );
    }

    // Initialize parameters
    final preparedKey = prepareEncrypt(secretKey.extractSync());

    // Create 16 byte nonce from a possibly shorter nonce.
    var nonceBytes = Uint8List(16);
    nonceBytes.setAll(0, nonce.bytes);
    if (keyStreamIndex != 0) {
      nonceBytes = Nonce(nonceBytes).increment(keyStreamIndex ~/ 16).bytes;
    }

    // Initialize output
    final output = Uint8List.fromList(input);

    // For each block
    for (var i = 0; i < input.length; i += 16) {
      // Encrypt nonce
      aesEncryptBlock(output, i, nonceBytes, 0, preparedKey);
      var blockLength = output.length - i;
      if (blockLength > 16) {
        blockLength = 16;
      }

      // XOR
      xorBlock(output, i, input, i, blockLength);

      // Increment nonce
      nonceBytes = Nonce(nonceBytes).increment().bytes;
    }
    return output;
  }
}
