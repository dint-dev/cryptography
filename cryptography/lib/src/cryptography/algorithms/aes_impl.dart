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

import 'aes_impl_block_function.dart';

void _xorBlock(
  List<int> result,
  int resultStart,
  List<int> arg,
  int argStart,
  int length,
) {
  for (var i = 0; i < length; i++) {
    result[resultStart + i] ^= arg[argStart + i];
  }
}

const Cipher aesCbc = _AesCbc();

const Cipher aesCtr = _AesCtr();

class _AesCbc extends Cipher {
  const _AesCbc();

  @override
  String get name => 'aesCbc';

  @override
  int get nonceLength => 16;

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
    if (nonce.bytes.length != 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be 16 bytes',
      );
    }
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be 0',
      );
    }
    final preparedKey = prepareDecrypt(secretKey.extractSync());
    final output = Uint8List(input.length);
    for (var i = 0; i < output.length; i += 16) {
      aesDecryptBlock(output, i, input, i, preparedKey);
      if (i == 0) {
        _xorBlock(output, i, nonce.bytes, 0, 16);
      } else {
        _xorBlock(output, i, input, i - 16, 16);
      }
    }

    // PKCS7 padding
    final paddingLength = output.last;
    if (paddingLength == 0 || paddingLength > 16) {
      throw StateError('Invalid padding length: $paddingLength');
    }
    for (var i = output.length - paddingLength; i < output.length; i++) {
      if (output[i] != paddingLength) {
        throw StateError('Missing padding');
      }
    }
    return Uint8List.view(
      output.buffer,
      output.offsetInBytes,
      output.length - paddingLength,
    );
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
    if (nonce.bytes.length != 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be 16 bytes',
      );
    }
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be 0',
      );
    }

    // PKCS7 padding
    final inputLength = input.length;
    final paddingLength = 16 - (inputLength % 16);
    final output = Uint8List(inputLength + paddingLength);
    output.setAll(0, input);
    output.fillRange(inputLength, output.length, paddingLength);

    final preparedKey = prepareEncrypt(secretKey.extractSync());
    for (var i = 0; i < output.length; i += 16) {
      if (i == 0) {
        _xorBlock(output, i, nonce.bytes, 0, 16);
      } else {
        _xorBlock(output, i, output, i - 16, 16);
      }
      aesEncryptBlock(output, i, output, i, preparedKey);
    }
    return output;
  }
}

class _AesCtr extends Cipher {
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
      _xorBlock(output, i, input, i, blockLength);

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
      _xorBlock(output, i, input, i, blockLength);

      // Increment nonce
      nonceBytes = Nonce(nonceBytes).increment().bytes;
    }
    return output;
  }
}
