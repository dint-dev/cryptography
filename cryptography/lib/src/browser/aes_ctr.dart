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
import 'package:js/js_util.dart' as js;

import 'aes.dart';
import 'javascript_bindings.dart' show jsArrayBufferFrom;
import 'javascript_bindings.dart' as web_crypto;

/// AES-CTR implementation that uses _Web Cryptography API_ in browsers.
class BrowserAesCtr extends AesCtr with BrowserAesMixin {
  @override
  final MacAlgorithm macAlgorithm;

  @override
  final int counterBits;

  @override
  final int secretKeyLength;

  const BrowserAesCtr({
    required this.macAlgorithm,
    this.secretKeyLength = 32,
    this.counterBits = 64,
  }) : super.constructor();

  @override
  String get webCryptoName => 'AES-CTR';

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    var cipherText = secretBox.cipherText;
    if (keyStreamIndex > 0) {
      final newCipherText = Uint8List(keyStreamIndex + cipherText.length);
      newCipherText.setAll(keyStreamIndex, cipherText);
      cipherText = newCipherText;
    }
    // Authenticate
    await secretBox.checkMac(
      macAlgorithm: macAlgorithm,
      secretKey: secretKey,
      aad: aad,
    );

    final counterBytes = Uint8List(16);
    counterBytes.setAll(0, secretBox.nonce);
    final jsCryptoKey = await jsCryptoKeyFromAesSecretKey(
      secretKey,
      webCryptoAlgorithm: 'AES-CTR',
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.decrypt(
        web_crypto.AesCtrParams(
          name: 'AES-CTR',
          counter: counterBytes.buffer,
          length: counterBits,
        ),
        jsCryptoKey,
        jsArrayBufferFrom(cipherText),
      ),
    );
    return List<int>.unmodifiable(
      Uint8List.view(byteBuffer, keyStreamIndex),
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
    if (keyStreamIndex > 0) {
      final tmp = Uint8List(keyStreamIndex + clearText.length);
      tmp.setAll(keyStreamIndex, clearText);
      clearText = tmp;
    }
    var counterBytes = Uint8List(16);
    counterBytes.setAll(0, nonce);
    final jsCryptoKey = await jsCryptoKeyFromAesSecretKey(
      secretKey,
      webCryptoAlgorithm: 'AES-CTR',
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.encrypt(
        web_crypto.AesCtrParams(
          name: 'AES-CTR',
          counter: counterBytes.buffer,
          length: counterBits,
        ),
        jsCryptoKey,
        jsArrayBufferFrom(clearText),
      ),
    );
    final cipherText = List<int>.unmodifiable(
      Uint8List.view(byteBuffer, keyStreamIndex),
    );

    final mac = await macAlgorithm.calculateMac(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );

    return SecretBox(
      cipherText,
      nonce: nonce,
      mac: mac,
    );
  }
}
