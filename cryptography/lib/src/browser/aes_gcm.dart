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

import 'dart:html' as html;
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:js/js_util.dart' as js;

import 'aes.dart';
import 'javascript_bindings.dart' show jsArrayBufferFrom;
import 'javascript_bindings.dart' as web_crypto;

/// AES-GCM implementation that uses _Web Cryptography API_ in browsers.
class BrowserAesGcm extends AesGcm
    with BrowserAesMixin
    implements StreamingCipher {
  @override
  final int secretKeyLength;

  @override
  final int nonceLength;

  /// Implementation used when:
  ///   * `keyStreamIndex` is non-zero.
  ///   * key is 192-bit.
  ///
  /// If null, [ArgumentError] will be thrown when `keyStreamIndex` is non-zero
  /// and 192-bit keys will not be accepted.
  final AesGcm? fallback;

  BrowserAesGcm({
    this.secretKeyLength = 32,
    this.nonceLength = 12,
    this.fallback,
  }) : super.constructor();

  @override
  String get webCryptoName => 'AES-GCM';

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    if (keyStreamIndex != 0) {
      final fallback = this.fallback;
      if (fallback == null) {
        throw ArgumentError.value(
          keyStreamIndex,
          'keyStreamIndex',
          'Must be 0',
        );
      }
      // Key stream offset can't be passed to Web Cryptography API.
      return fallback.decrypt(
        secretBox,
        secretKey: secretKey,
        aad: aad,
        keyStreamIndex: keyStreamIndex,
      );
    }

    if (secretKey is SecretKeyData && secretKey.bytes.length == 24) {
      final fallback = this.fallback;
      if (fallback == null) {
        throw ArgumentError.value(
          secretKey,
          'secretKey',
        );
      }
      // Key stream offset can't be passed to Web Cryptography API.
      return fallback.decrypt(
        secretBox,
        secretKey: secretKey,
        aad: aad,
        keyStreamIndex: keyStreamIndex,
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
    final jsCryptoKey = await jsCryptoKeyFromAesSecretKey(
      secretKey,
      webCryptoAlgorithm: 'AES-GCM',
    );
    final cipherText = secretBox.cipherText;
    final macBytes = actualMac.bytes;
    final cipherTextAndMac = Uint8List(cipherText.length + macBytes.length);
    cipherTextAndMac.setAll(0, cipherText);
    cipherTextAndMac.setAll(cipherText.length, macBytes);
    try {
      final byteBuffer = await js.promiseToFuture<ByteBuffer>(
        web_crypto.decrypt(
          web_crypto.AesGcmParams(
            name: 'AES-GCM',
            iv: jsArrayBufferFrom(secretBox.nonce),
            additionalData: jsArrayBufferFrom(aad),
            tagLength: macBytes.length * 8,
          ),
          jsCryptoKey,
          jsArrayBufferFrom(cipherTextAndMac),
        ),
      );
      return Uint8List.view(byteBuffer);
    } on html.DomException catch (e) {
      if (e.name == 'OperationError') {
        throw SecretBoxAuthenticationError(secretBox: secretBox);
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
  }) async {
    // Key stream offset can't be passed to Web Cryptography API.
    if (keyStreamIndex != 0) {
      final fallback = this.fallback;
      if (fallback == null) {
        throw ArgumentError.value(
          keyStreamIndex,
          'keyStreamIndex',
          'Must be 0',
        );
      }
      return fallback.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
        keyStreamIndex: keyStreamIndex,
      );
    }

    nonce ??= newNonce();
    final jsCryptoKey = await jsCryptoKeyFromAesSecretKey(
      secretKey,
      webCryptoAlgorithm: 'AES-GCM',
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.encrypt(
        web_crypto.AesGcmParams(
          name: 'AES-GCM',
          iv: jsArrayBufferFrom(nonce),
          additionalData: jsArrayBufferFrom(aad),
          tagLength: macAlgorithm.macLength * 8,
        ),
        jsCryptoKey,
        jsArrayBufferFrom(clearText),
      ),
    );
    final cipherText = List<int>.unmodifiable(
      Uint8List.view(byteBuffer, 0, clearText.length),
    );
    final mac = Mac(List<int>.unmodifiable(
      Uint8List.view(byteBuffer, clearText.length),
    ));
    return SecretBox(
      cipherText,
      nonce: nonce,
      mac: mac,
    );
  }
}
