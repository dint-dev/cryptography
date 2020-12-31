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

import 'javascript_bindings.dart' show jsArrayBufferFrom;
import 'javascript_bindings.dart' as web_crypto;

Future<web_crypto.CryptoKey> jsCryptoKeyFromAesSecretKey(
  SecretKey secretKey, {
  required String webCryptoAlgorithm,
}) async {
  final secretKeyData = await secretKey.extract();
  return js.promiseToFuture(web_crypto.importKey(
    'raw',
    jsArrayBufferFrom(secretKeyData.bytes),
    webCryptoAlgorithm,
    false,
    ['encrypt', 'decrypt'],
  ));
}

mixin BrowserAesMixin implements Cipher {
  String get webCryptoName;

  @override
  Future<SecretKey> newSecretKey() async {
    final jsCryptoKeyFuture = js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.generateKey(
        web_crypto.AesKeyGenParams(
          name: webCryptoName,
          length: secretKeyLength * 8,
        ),
        true,
        ['encrypt', 'decrypt'],
      ),
    );

    return SecretKey.lazy(() async {
      final byteBuffer = await js.promiseToFuture(
        web_crypto.exportKey('raw', await jsCryptoKeyFuture),
      );
      final bytes = List<int>.unmodifiable(Uint8List.view(byteBuffer));
      return SecretKeyData(bytes);
    });
  }
}
