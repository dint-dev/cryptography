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

const Cipher dartAesCbc = _AesCbc();

class _AesCbc extends AesCipher {
  const _AesCbc();

  @override
  String get name => 'aesCbc';

  @override
  int get nonceLength => 16;

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
        xorBlock(output, i, nonce.bytes, 0, 16);
      } else {
        xorBlock(output, i, input, i - 16, 16);
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
        xorBlock(output, i, nonce.bytes, 0, 16);
      } else {
        xorBlock(output, i, output, i - 16, 16);
      }
      aesEncryptBlock(output, i, output, i, preparedKey);
    }
    return output;
  }
}
