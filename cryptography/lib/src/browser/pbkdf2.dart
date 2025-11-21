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

import 'package:cryptography/cryptography.dart';

import '_javascript_bindings.dart' as web_crypto;
import '_javascript_bindings.dart' show jsUint8ListFrom;
import 'hmac.dart';

/// PBKDF2 implementation that uses _Web Cryptography API_ in browsers.
///
/// See [BrowserCryptography].
class BrowserPbkdf2 extends Pbkdf2 {
  @override
  final BrowserHmac macAlgorithm;

  @override
  final int bits;

  @override
  final int iterations;

  const BrowserPbkdf2({
    required this.macAlgorithm,
    required this.bits,
    required this.iterations,
  }) : super.constructor();

  @override
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
  }) async {
    final jsCryptoKey = await _jsCryptoKey(secretKey);

    // subtle.deriveBits(...)
    final derivedBytes = await web_crypto.deriveBits(
      web_crypto.Pkdf2Params(
        name: 'PBKDF2'.toJS,
        hash: macAlgorithm.hashAlgorithmWebCryptoName.toJS,
        salt: jsUint8ListFrom(nonce),
        iterations: iterations.toJS,
      ).jsObject,
      jsCryptoKey,
      bits.toJS,
    );

    return SecretKey(derivedBytes);
  }

  Future<web_crypto.CryptoKey> _jsCryptoKey(SecretKey secretKey) async {
    final secretKeyData = await secretKey.extract();
    return web_crypto.importKeyWhenRaw(
      jsUint8ListFrom(secretKeyData.bytes),
      'PBKDF2'.toJS,
      false.toJS,
      ['deriveBits'.toJS].toJS,
    );
  }
}
