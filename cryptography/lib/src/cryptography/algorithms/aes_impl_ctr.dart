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
import 'package:cryptography/src/utils/bytes.dart';
import 'package:cryptography/src/utils/parameters.dart';
import 'package:meta/meta.dart';

import 'aes_impl.dart';

const Cipher dartAesCtr = _AesCtr();

class _AesCtr extends AesCipher {
  const _AesCtr();

  @override
  String get name => 'aesCtr';

  @override
  int get nonceLength => 16;

  @override
  int get nonceLengthMin => 12;

  @override
  int get nonceLengthMax => 16;

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    // Encryption function can be used for decrypting too.
    return encryptSync(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Uint8List encryptSync(
    List<int> plainText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    // Check arguments
    final secretKeyBytes = secretKey.extractSync();
    checkCipherParameters(
      this,
      secretKeyLength: secretKeyBytes.length,
      nonce: nonce,
      aad: aad != null,
      keyStreamIndex: keyStreamIndex,
      // TODO: Support any keyStreamIndex
      keyStreamFactor: 1,
    );

    // Create 16 byte nonce from a possibly shorter nonce.
    final nonceAsUint8List = Uint8List(16);
    nonceAsUint8List.setAll(0, nonce.bytes);
    final nonceAsUint32List = Uint32List.view(nonceAsUint8List.buffer);

    // Append key stream index
    if (keyStreamIndex != 0) {
      bytesAsBigEndianAddInt(nonceAsUint8List, keyStreamIndex ~/ 16);
    }

    // Allocate output bytes
    final outputAsUint32List = Uint32List(
      (keyStreamIndex % 16 + plainText.length + 15) ~/ 16 * 4,
    );

    // Expand AES key
    final preparedKey = aesExpandKeyForEncrypting(
      secretKey,
      secretKeyBytes,
    );

    // For each block
    for (var i = 0; i < outputAsUint32List.length; i += 4) {
      // Encrypt nonce with AES
      aesEncryptBlock(
        outputAsUint32List,
        i,
        nonceAsUint32List,
        0,
        preparedKey,
      );

      // Increment nonce.
      bytesAsBigEndianAddInt(nonceAsUint8List, 1);
    }

    // Construct the returned view
    final outputAsUint8List = Uint8List.view(
      outputAsUint32List.buffer,
      keyStreamIndex % 16,
      plainText.length,
    );

    // output ^= plainText
    for (var i = 0; i < plainText.length; i++) {
      outputAsUint8List[i] ^= plainText[i];
    }

    return outputAsUint8List;
  }
}
