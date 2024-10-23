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

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';

import '_javascript_bindings.dart' show jsArrayBufferFrom;
import '_javascript_bindings.dart' as web_crypto;
import 'browser_secret_key.dart';

/// AES-CTR implementation that uses _Web Cryptography API_ in browsers.
class BrowserAesCtr extends AesCtr {
  static const String _webCryptoName = 'AES-CTR';

  @override
  final MacAlgorithm macAlgorithm;

  @override
  final int counterBits;

  @override
  final int secretKeyLength;

  final Random? _random;

  const BrowserAesCtr({
    required this.macAlgorithm,
    this.secretKeyLength = 32,
    this.counterBits = 64,
    Random? random,
  })  : _random = random,
        super.constructor(random: random);

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) async {
    var cipherText = secretBox.cipherText;
    if (keyStreamIndex != 0) {
      if (keyStreamIndex < 0) {
        throw ArgumentError.value(keyStreamIndex, 'keyStreamIndex');
      }
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
    final jsCryptoKey = await BrowserSecretKey.jsCryptoKeyForAes(
      secretKey,
      secretKeyLength: secretKeyLength,
      webCryptoAlgorithm: _webCryptoName,
      isExtractable: false,
      allowEncrypt: false,
      allowDecrypt: true,
    );
    final byteBuffer = await web_crypto.decrypt(
      web_crypto.AesCtrParams(
        name: _webCryptoName,
        counter: counterBytes.buffer,
        length: counterBits,
      ),
      jsCryptoKey,
      jsArrayBufferFrom(cipherText),
    );
    return Uint8List.view(byteBuffer, keyStreamIndex);
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
    nonce ??= newNonce();
    if (keyStreamIndex != 0) {
      if (keyStreamIndex < 0) {
        throw ArgumentError.value(keyStreamIndex, 'keyStreamIndex');
      }
      final tmp = Uint8List(keyStreamIndex + clearText.length);
      tmp.setAll(keyStreamIndex, clearText);
      clearText = tmp;
    }
    var counterBytes = Uint8List(16);
    counterBytes.setAll(0, nonce);
    final jsCryptoKey = await BrowserSecretKey.jsCryptoKeyForAes(
      secretKey,
      secretKeyLength: secretKeyLength,
      webCryptoAlgorithm: _webCryptoName,
      isExtractable: false,
      allowEncrypt: true,
      allowDecrypt: false,
    );
    final byteBuffer = await web_crypto.encrypt(
      web_crypto.AesCtrParams(
        name: _webCryptoName,
        counter: counterBytes.buffer,
        length: counterBits,
      ),
      jsCryptoKey,
      jsArrayBufferFrom(clearText),
    );
    final cipherText = Uint8List.view(byteBuffer, keyStreamIndex);

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

  @override
  Future<BrowserSecretKey> newSecretKey({
    bool isExtractable = true,
    bool allowEncrypt = true,
    bool allowDecrypt = true,
  }) async {
    return BrowserSecretKey.generateForAes(
      webCryptoAlgorithm: _webCryptoName,
      secretKeyLength: secretKeyLength,
      isExtractable: isExtractable,
      allowEncrypt: allowEncrypt,
      allowDecrypt: allowDecrypt,
      random: _random,
    );
  }
}
