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
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:meta/meta.dart';

import '_javascript_bindings.dart' as web_crypto;

class BrowserX25519 extends X25519 {
  static final _jsAlgorithm = web_crypto.AlgorithmNameParams(
    name: 'X25519'.toJS,
  ).jsObject;

  final X25519? _fallback;

  @literal
  const BrowserX25519({required X25519? fallback})
      : _fallback = fallback,
        super.constructor();

  @override
  Future<SimpleKeyPair> newKeyPair() async {
    late web_crypto.Jwk jwk;
    try {
      final jsCryptoKey = await web_crypto.generateKeyWhenKeyPair(
          _jsAlgorithm, true.toJS, ['deriveBits'.toJS].toJS);
      jwk = await web_crypto.exportKeyWhenJwk(jsCryptoKey.privateKey);
    } catch (e) {
      final fallback = _fallback;
      if (fallback != null) {
        return fallback.newKeyPair();
      }
      throw StateError('$runtimeType.newKeyPair(...) failed: $e');
    }
    return SimpleKeyPairData(
      Uint8List.fromList(web_crypto.base64UrlDecode(jwk.d!.toDart)),
      publicKey: SimplePublicKey(
        Uint8List.fromList(web_crypto.base64UrlDecode(jwk.x!.toDart)),
        type: KeyPairType.x25519,
      ),
      type: KeyPairType.ed25519,
    );
  }

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed) {
    KeyPairType.x25519.checkPrivateKeyBytesFormat(seed);
    return DartX25519().newKeyPairFromSeed(seed);
  }

  @override
  Future<SecretKey> sharedSecretKey(
      {required KeyPair keyPair, required PublicKey remotePublicKey}) async {
    final simplePublicKey = remotePublicKey as SimplePublicKey;
    KeyPairType.x25519.checkPublicKeyBytesFormat(simplePublicKey.bytes);

    late web_crypto.CryptoKey jsPrivateKey;
    try {
      final keyPairData = await (keyPair as SimpleKeyPair).extract();
      KeyPairType.ed25519.checkPrivateKeyBytesFormat(keyPairData.bytes);
      jsPrivateKey = await web_crypto.importKeyWhenJwk(
        web_crypto.Jwk(
          kty: 'OKP'.toJS,
          crv: 'X25519'.toJS,
          d: web_crypto.base64UrlEncode(keyPairData.bytes).toJS,
          x: web_crypto.base64UrlEncode(keyPairData.publicKey.bytes).toJS,
        ),
        _jsAlgorithm,
        false.toJS,
        ['deriveBits'.toJS].toJS,
      );
    } catch (e) {
      final fallback = _fallback;
      if (fallback != null) {
        return fallback.sharedSecretKey(
          keyPair: keyPair,
          remotePublicKey: remotePublicKey,
        );
      }
      throw StateError(
          '$runtimeType.sharedSecretKey(...) failed to construct JS private key: $e');
    }
    late web_crypto.CryptoKey jsPublicKey;
    try {
      jsPublicKey = await web_crypto.importKeyWhenJwk(
        web_crypto.Jwk(
          kty: 'OKP'.toJS,
          crv: 'X25519'.toJS,
          x: web_crypto.base64UrlEncode(simplePublicKey.bytes).toJS,
        ),
        _jsAlgorithm,
        false.toJS,
        <JSString>[].toJS,
      );
    } catch (e) {
      throw StateError(
          '$runtimeType.sharedSecretKey(...) failed to construct JS public key: $e');
    }
    try {
      final bytes = await web_crypto.deriveBits(
        web_crypto.DeriveParamsWhenPublicKey(
          name: 'X25519'.toJS,
          public: jsPublicKey,
        ).jsObject,
        jsPrivateKey,
        256.toJS,
      );
      return SecretKey(bytes);
    } catch (e) {
      throw StateError('$runtimeType.sharedSecretKey(...) failed: $e');
    }
  }
}
