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

import '../../cryptography_plus.dart';
import '../../helpers.dart';
import '_javascript_bindings.dart' as web_crypto;
import '_javascript_bindings.dart';

class BrowserSecretKey extends SecretKey {
  web_crypto.CryptoKey? _jsCryptoKey;

  final int length;

  @override
  final bool isExtractable;

  @override
  final bool allowEncrypt;

  @override
  final bool allowDecrypt;

  SecretKeyData? _secretKeyData;

  BrowserSecretKey({
    required web_crypto.CryptoKey jsCryptoKey,
    required this.length,
    required this.isExtractable,
    required this.allowEncrypt,
    required this.allowDecrypt,
  })  : _jsCryptoKey = jsCryptoKey,
        super.constructor();

  @override
  int get hashCode => jsCryptoKey.hashCode;

  /// Javascript object that can be used in WebCrypto API.
  web_crypto.CryptoKey get jsCryptoKey {
    final existing = _jsCryptoKey;
    if (existing != null) {
      return existing;
    }
    throw StateError(
      'The Web Cryptography secret key has been destroyed.',
    );
  }

  @override
  bool operator ==(Object other) =>
      other is BrowserSecretKey &&
      identical(jsCryptoKey, other.jsCryptoKey) &&
      isExtractable == other.isExtractable &&
      allowEncrypt == other.allowEncrypt &&
      allowDecrypt == other.allowDecrypt;

  BrowserSecretKey copy() {
    return BrowserSecretKey(
      jsCryptoKey: jsCryptoKey,
      length: length,
      isExtractable: isExtractable,
      allowEncrypt: allowEncrypt,
      allowDecrypt: allowDecrypt,
    );
  }

  @override
  void destroy() {
    _jsCryptoKey = null;
  }

  @override
  Future<SecretKeyData> extract() async {
    if (!isExtractable) {
      throw UnsupportedError(
        'The Web Cryptography secret key is not extractable.',
      );
    }
    final existing = _secretKeyData;
    if (existing != null) {
      return existing;
    }
    try {
      final byteBuffer = await web_crypto.exportKeyWhenRaw(jsCryptoKey);
      final bytes = Uint8List.view(byteBuffer);
      final secretKeyData = SecretKeyData(
        bytes,
        overwriteWhenDestroyed: true,
      );
      _secretKeyData = secretKeyData;
      return secretKeyData;
    } catch (error, stackTrace) {
      throw StateError(
        'Web Cryptography throw an error: $error\n$stackTrace',
      );
    }
  }

  @override
  String toString() => 'BrowserSecretKey(\n'
      '  ...,\n'
      '  isExtractable: $isExtractable,\n'
      '  allowEncrypt: $allowEncrypt,\n'
      '  allowDecrypt: $allowDecrypt\n'
      ')';

  /// Generates a new secret key.
  static Future<BrowserSecretKey> generateForAes({
    required String webCryptoAlgorithm,
    required int secretKeyLength,
    required bool isExtractable,
    required bool allowEncrypt,
    required bool allowDecrypt,
    required Random? random,
  }) async {
    final usages = [
      if (allowEncrypt) 'encrypt',
      if (allowDecrypt) 'decrypt',
    ];
    if (random != null) {
      final bytes = Uint8List(secretKeyLength);
      fillBytesWithSecureRandom(bytes, random: random);
      final jsCryptoKey = await web_crypto.importKeyWhenRaw(
        web_crypto.jsArrayBufferFrom(bytes),
        webCryptoAlgorithm,
        isExtractable,
        usages,
      );
      return BrowserSecretKey(
        jsCryptoKey: jsCryptoKey,
        length: secretKeyLength,
        isExtractable: isExtractable,
        allowEncrypt: allowEncrypt,
        allowDecrypt: allowDecrypt,
      );
    }
    final jsCryptoKey = await web_crypto.generateKeyWhenKey(
      web_crypto.AesKeyGenParams(
        name: webCryptoAlgorithm,
        length: secretKeyLength * 8,
      ),
      isExtractable,
      usages,
    );
    return BrowserSecretKey(
      jsCryptoKey: jsCryptoKey,
      length: secretKeyLength,
      isExtractable: isExtractable,
      allowEncrypt: allowEncrypt,
      allowDecrypt: allowDecrypt,
    );
  }

  /// Returns Javascript object that can be used in WebCrypto API.
  static Future<web_crypto.CryptoKey> jsCryptoKeyForAes(
    SecretKey secretKey, {
    required String webCryptoAlgorithm,
    required int secretKeyLength,
    required bool isExtractable,
    required bool allowEncrypt,
    required bool allowDecrypt,
  }) async {
    if (secretKey is BrowserSecretKey) {
      final actualSecretKeyLength = secretKey.length;
      if (actualSecretKeyLength != secretKeyLength) {
        throw _secretKeyLengthError(actualSecretKeyLength, secretKeyLength);
      }
      return secretKey.jsCryptoKey;
    }
    final secretKeyBytes = await secretKey.extractBytes();
    final actualSecretKeyLength = secretKeyBytes.length;
    if (actualSecretKeyLength != secretKeyLength) {
      throw _secretKeyLengthError(actualSecretKeyLength, secretKeyLength);
    }
    return web_crypto.importKeyWhenRaw(
      jsArrayBufferFrom(secretKeyBytes),
      webCryptoAlgorithm,
      isExtractable,
      [
        if (allowEncrypt) 'encrypt',
        if (allowDecrypt) 'decrypt',
      ],
    );
  }

  static ArgumentError _secretKeyLengthError(int actual, int expected) {
    return ArgumentError(
      'Secret key is ${actual * 8} bits, expected ${expected * 8} bits.',
    );
  }
}
