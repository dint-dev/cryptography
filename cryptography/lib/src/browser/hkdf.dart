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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/src/browser/hash.dart';

import '_javascript_bindings.dart' show jsArrayBufferFrom;
import '_javascript_bindings.dart' as web_crypto;

/// HKDF implementation that uses _Web Cryptography API_ in browsers.
///
/// See [BrowserCryptography].
class BrowserHkdf extends Hkdf {
  @override
  final Hmac hmac;

  @override
  final int outputLength;

  const BrowserHkdf({required this.hmac, required this.outputLength})
      : super.constructor();

  @override
  Future<SecretKeyData> deriveKey({
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> info = const <int>[],
  }) async {
    final jsCryptoKey = await _jsCryptoKey(secretKey);
    final byteBuffer = await web_crypto.deriveBits(
      web_crypto.HkdfParams(
        name: 'HKDF',
        hash: BrowserHashAlgorithmMixin.hashAlgorithmNameFor(
          hmac.hashAlgorithm,
        )!,
        salt: jsArrayBufferFrom(nonce),
        info: jsArrayBufferFrom(info),
      ),
      jsCryptoKey,
      8 * outputLength,
    );
    return SecretKeyData(Uint8List.view(byteBuffer));
  }

  Future<web_crypto.CryptoKey> _jsCryptoKey(SecretKey secretKey) async {
    final secretKeyBytes = await secretKey.extractBytes();
    return await web_crypto.importKeyWhenRaw(
      web_crypto.jsArrayBufferFrom(secretKeyBytes),
      'HKDF',
      false,
      const ['deriveBits'],
    );
  }
}
