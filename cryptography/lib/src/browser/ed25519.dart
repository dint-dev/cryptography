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
import 'package:cryptography/dart.dart';
import 'package:meta/meta.dart';

import '_javascript_bindings.dart' as web_crypto;

class BrowserEd25519 extends Ed25519 {
  static final _jsAlgorithm = web_crypto.AlgorithmNameParams(
    name: 'Ed25519'.toJS,
  ).jsObject;

  final Ed25519? _fallback;

  @literal
  const BrowserEd25519({required Ed25519? fallback})
      : _fallback = fallback,
        super.constructor();

  @override
  Future<SimpleKeyPair> newKeyPair() async {
    late web_crypto.Jwk jwk;
    try {
      final jsCryptoKey = await web_crypto.generateKeyWhenKeyPair(
          _jsAlgorithm, true.toJS, ['sign'.toJS, 'verify'.toJS].toJS);
      jwk = await web_crypto.exportKeyWhenJwk(jsCryptoKey.privateKey);
    } catch (e) {
      final fallback = _fallback;
      if (fallback != null) {
        return fallback.newKeyPair();
      }
      throw StateError('$runtimeType.newKeyPair(...) failed: $e');
    }
    return SimpleKeyPairData(
      web_crypto.base64UrlDecode(jwk.d!.toDart),
      publicKey: SimplePublicKey(
        web_crypto.base64UrlDecode(jwk.x!.toDart),
        type: KeyPairType.ed25519,
      ),
      type: KeyPairType.ed25519,
    );
  }

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed) {
    KeyPairType.ed25519.checkPrivateKeyBytesFormat(seed);
    return DartEd25519().newKeyPairFromSeed(seed);
  }

  @override
  Future<Signature> sign(List<int> message, {required KeyPair keyPair}) async {
    try {
      final publicKeyFuture = keyPair.extractPublicKey();
      final keyPairData = await (keyPair as SimpleKeyPair).extract();
      final jsCryptoKey = await web_crypto.importKeyWhenJwk(
        web_crypto.Jwk(
          kty: 'OKP'.toJS,
          crv: 'Ed25519'.toJS,
          d: web_crypto.base64UrlEncode(keyPairData.bytes).toJS,
          x: web_crypto.base64UrlEncode(keyPairData.publicKey.bytes).toJS,
        ),
        _jsAlgorithm,
        false.toJS,
        ['sign'.toJS].toJS,
      );
      final signature = await web_crypto.sign(
        _jsAlgorithm,
        jsCryptoKey,
        web_crypto.jsUint8ListFrom(message),
      );
      return Signature(
        signature,
        publicKey: await publicKeyFuture,
      );
    } catch (e) {
      final fallback = _fallback;
      if (fallback != null) {
        return fallback.sign(message, keyPair: keyPair);
      }
      throw StateError('$runtimeType.sign(...) failed: $e');
    }
  }

  @override
  Future<bool> verify(List<int> message, {required Signature signature}) async {
    Ed25519.checkSignatureLength(signature.bytes.length);
    final simplePublicKey = signature.publicKey as SimplePublicKey;
    KeyPairType.ed25519.checkPublicKeyBytesFormat(simplePublicKey.bytes);
    try {
      final jsPublicKey = await web_crypto.importKeyWhenRaw(
        web_crypto.jsUint8ListFrom(simplePublicKey.bytes),
        _jsAlgorithm,
        true.toJS,
        ['verify'.toJS].toJS,
      );
      return web_crypto.verify(
        _jsAlgorithm,
        jsPublicKey,
        web_crypto.jsUint8ListFrom(signature.bytes),
        web_crypto.jsUint8ListFrom(message),
      );
    } catch (e) {
      final fallback = _fallback;
      if (fallback != null) {
        return fallback.verify(message, signature: signature);
      }
      throw StateError('$runtimeType.verify(...) failed: $e');
    }
  }
}
