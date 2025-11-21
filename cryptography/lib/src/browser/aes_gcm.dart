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

import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/browser/browser_secret_key.dart';

import '_javascript_bindings.dart' as web_crypto;
import '_javascript_bindings.dart' show jsUint8ListFrom;

/// AES-GCM implementation that uses _Web Cryptography API_ in browsers.
class BrowserAesGcm extends AesGcm implements StreamingCipher {
  static const String _webCryptoName = 'AES-GCM';

  @override
  final int secretKeyLength;

  @override
  final int nonceLength;

  /// Fallback is the implementation used when `keyStreamIndex` is non-zero.
  ///
  /// If null, [ArgumentError] will be thrown when `keyStreamIndex` is non-zero.
  final AesGcm? fallback;

  final Random? _random;

  BrowserAesGcm({
    this.secretKeyLength = 32,
    this.nonceLength = AesGcm.defaultNonceLength,
    this.fallback,
    super.random,
  })  : _random = random,
        super.constructor();

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) async {
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be 0',
      );
    }

    final actualMac = secretBox.mac;
    final actualMacLength = actualMac.bytes.length;
    final expectedMacLength = macAlgorithm.macLength;
    if (actualMacLength != expectedMacLength) {
      throw ArgumentError.value(
        secretBox,
        'secretBox',
        'Expected MAC length $expectedMacLength, actually $actualMacLength',
      );
    }
    final jsCryptoKey = await BrowserSecretKey.jsCryptoKeyForAes(
      secretKey,
      secretKeyLength: secretKeyLength,
      webCryptoAlgorithm: _webCryptoName,
      isExtractable: false,
      allowEncrypt: false,
      allowDecrypt: true,
    );
    final cipherText = secretBox.cipherText;
    final macBytes = actualMac.bytes;
    final cipherTextAndMac = Uint8List(cipherText.length + macBytes.length);
    cipherTextAndMac.setAll(0, cipherText);
    cipherTextAndMac.setAll(cipherText.length, macBytes);
    try {
      final byteBuffer = await web_crypto.decrypt(
        web_crypto.AesGcmParams(
          name: _webCryptoName.toJS,
          iv: jsUint8ListFrom(secretBox.nonce),
          additionalData: jsUint8ListFrom(aad),
          tagLength: (macBytes.length * 8).toJS,
        ).jsObject,
        jsCryptoKey,
        jsUint8ListFrom(cipherTextAndMac),
      );
      return Uint8List.view(byteBuffer);
    } catch (e) {
      final js = JSObject.fromInteropObject(e);
      if (js.hasProperty('name'.toJS).toDart) {
        final name = (js.getProperty('name'.toJS) as JSString).toDart;
        if (name == 'OperationError') {
          throw SecretBoxAuthenticationError();
        }
      }
      rethrow;
    }
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
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be 0',
      );
    }

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
      web_crypto.AesGcmParams(
        name: 'AES-GCM'.toJS,
        iv: jsUint8ListFrom(nonce),
        additionalData: jsUint8ListFrom(aad),
        tagLength: (macAlgorithm.macLength * 8).toJS,
      ).jsObject,
      jsCryptoKey,
      jsUint8ListFrom(clearText),
    );

    final cipherText = Uint8List.view(
      byteBuffer,
      0,
      clearText.length,
    );

    final mac = Mac(Uint8List.view(byteBuffer, clearText.length));

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
