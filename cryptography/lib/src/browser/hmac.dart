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

import 'dart:js_util' as js;
import 'dart:typed_data';

import 'package:cryptography/browser.dart';
import 'package:cryptography/cryptography.dart';

import 'hash.dart';
import 'javascript_bindings.dart' as web_crypto;
import 'javascript_bindings.dart' show jsArrayBufferFrom;

/// HMAC implementation that uses _Web Cryptography API_ in browsers.
///
/// See [BrowserCryptography].
class BrowserHmac extends Hmac {
  /// HMAC-SHA-1.
  static const BrowserHmac sha1 = BrowserHmac._(BrowserSha1(), 'SHA-1');

  /// HMAC-SHA256.
  static const BrowserHmac sha256 = BrowserHmac._(BrowserSha256(), 'SHA-256');

  /// HMAC-SHA384.
  static const BrowserHmac sha384 = BrowserHmac._(BrowserSha384(), 'SHA-384');

  /// HMAC-SHA512.
  static const BrowserHmac sha512 = BrowserHmac._(BrowserSha512(), 'SHA-512');

  @override
  final BrowserHashAlgorithmMixin hashAlgorithm;

  final String hashAlgorithmWebCryptoName;

  const BrowserHmac._(this.hashAlgorithm, this.hashAlgorithmWebCryptoName)
      : super.constructor();

  @override
  Future<Mac> calculateMac(
    List<int> bytes, {
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    if (aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad', 'AAD is unsupported by HMAC');
    }
    final jsCryptoKey = await _jsCryptoKey(secretKey);
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.sign(
        'HMAC',
        jsCryptoKey,
        jsArrayBufferFrom(bytes),
      ),
    );
    return Mac(List<int>.unmodifiable(
      Uint8List.view(byteBuffer),
    ));
  }

  Future<web_crypto.CryptoKey> _jsCryptoKey(SecretKey secretKey) async {
    final secretKeyBytes = await secretKey.extractBytes();
    if (secretKeyBytes.isEmpty) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'SecretKey bytes must be non-empty',
      );
    }
    return await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.importKey(
        'raw',
        web_crypto.jsArrayBufferFrom(secretKeyBytes),
        web_crypto.HmacImportParams(
          name: 'HMAC',
          hash: hashAlgorithmWebCryptoName,
        ),
        false,
        const ['sign'],
      ),
    );
  }
}
