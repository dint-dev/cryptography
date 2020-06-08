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

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide aesGcm, AesGcm;
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:flutter/foundation.dart';
import 'package:meta/meta.dart';

import 'plugin.dart';

const Cipher aesGcm = cryptography.aesGcm;

/// {@nodoc}
@visibleForTesting
// ignore: invalid_use_of_visible_for_testing_member
class AesGcm extends cryptography.AesGcm {
  const AesGcm();

  @override
  Future<Uint8List> decrypt(
    List<int> cipherText, {
    SecretKey secretKey,
    Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    aad ??= const <int>[];
    if (aad.isEmpty &&
        keyStreamIndex == 0 &&
        cipherText.length > 128 &&
        (Platform.isIOS || Platform.isMacOS)) {
      final result = await channel.invokeMethod(
        'aes_gcm_decrypt',
        {
          'data': Uint8List.fromList(getDataInCipherText(cipherText)),
          'key': Uint8List.fromList(await secretKey.extract()),
          'nonce': Uint8List.fromList(nonce.bytes),
          'tag': Uint8List.fromList(getMacInCipherText(cipherText).bytes),
        },
      );
      if (result is Uint8List) {
        return result;
      } else if (result == 'old_operating_system') {
        // Ignore
      } else {
        throw StateError('Invalid output from plugin: $result');
      }
    }
    return super.decrypt(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<Uint8List> encrypt(
    List<int> plainText, {
    SecretKey secretKey,
    Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    aad ??= const <int>[];
    if (aad.isEmpty &&
        keyStreamIndex == 0 &&
        plainText.length > 128 &&
        (Platform.isIOS || Platform.isMacOS)) {
      final result = await channel.invokeMethod(
        'aes_gcm_encrypt',
        {
          'data': Uint8List.fromList(plainText),
          'key': Uint8List.fromList(await secretKey.extract()),
          'nonce': Uint8List.fromList(nonce.bytes),
        },
      );
      if (result is Map) {
        final cipherText = result['cipherText'] as Uint8List;
        final tag = result['tag'] as Uint8List;
        final tmp = Uint8List(cipherText.length + tag.length);
        tmp.setAll(0, cipherText);
        tmp.setAll(cipherText.length, tag);
        return tmp;
      } else if (result == 'old_operating_system') {
        // Ignore
      } else {
        throw StateError('Invalid output from plugin: $result');
      }
    }
    return super.encrypt(
      plainText,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }
}
