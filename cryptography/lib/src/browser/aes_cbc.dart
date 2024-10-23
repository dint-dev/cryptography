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

/// AES-CBC implementation that uses _Web Cryptography API_ in browsers.
///
/// Web Cryptography API supports only PKCS7 padding.
class BrowserAesCbc extends AesCbc {
  static const String _webCryptoName = 'AES-CBC';

  @override
  final MacAlgorithm macAlgorithm;

  @override
  final int secretKeyLength;

  final Random? _random;

  const BrowserAesCbc({
    required this.macAlgorithm,
    this.secretKeyLength = 32,
    Random? random,
  })  : _random = random,
        super.constructor(random: random);

  @override
  PaddingAlgorithm get paddingAlgorithm => PaddingAlgorithm.pkcs7;

  @override
  Future<Uint8List> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    Uint8List? possibleBuffer,
  }) async {
    // Authenticate
    await secretBox.checkMac(
      macAlgorithm: macAlgorithm,
      secretKey: secretKey,
      aad: aad,
    );

    final jsCryptoKey = await BrowserSecretKey.jsCryptoKeyForAes(
      secretKey,
      secretKeyLength: secretKeyLength,
      webCryptoAlgorithm: _webCryptoName,
      isExtractable: false,
      allowEncrypt: false,
      allowDecrypt: true,
    );
    final byteBuffer = await web_crypto.decrypt(
      web_crypto.AesCbcParams(
        name: _webCryptoName,
        iv: jsArrayBufferFrom(secretBox.nonce),
      ),
      jsCryptoKey,
      jsArrayBufferFrom(secretBox.cipherText),
    );
    return Uint8List.view(byteBuffer);
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

    final jsCryptoKey = await BrowserSecretKey.jsCryptoKeyForAes(
      secretKey,
      secretKeyLength: secretKeyLength,
      webCryptoAlgorithm: _webCryptoName,
      isExtractable: false,
      allowEncrypt: true,
      allowDecrypt: false,
    );
    final byteBuffer = await web_crypto.encrypt(
      web_crypto.AesCbcParams(
        name: _webCryptoName,
        iv: jsArrayBufferFrom(nonce),
      ),
      jsCryptoKey,
      jsArrayBufferFrom(clearText),
    );
    final cipherText = Uint8List.view(byteBuffer);

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
