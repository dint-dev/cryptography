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
import 'dart:math';

import 'package:cryptography/cryptography.dart';

import '_javascript_bindings.dart' as web_crypto;
import 'browser_ec_key_pair.dart';

class BrowserEcdh extends Ecdh {
  final int length;

  @override
  final KeyPairType keyPairType;

  /// ECDH with P-256.
  factory BrowserEcdh.p256({
    required int length,
    Random? random,
  }) {
    return BrowserEcdh._(
      KeyPairType.p256,
      length: length,
    );
  }

  /// ECDH with P-384.
  factory BrowserEcdh.p384({
    required int length,
    Random? random,
  }) {
    return BrowserEcdh._(
      KeyPairType.p384,
      length: length,
    );
  }

  /// ECDH with P-521.
  factory BrowserEcdh.p521({
    required int length,
    Random? random,
  }) {
    return BrowserEcdh._(
      KeyPairType.p521,
      length: length,
    );
  }

  const BrowserEcdh._(
    this.keyPairType, {
    required this.length,
  }) : super.constructor();

  @override
  Future<EcKeyPair> newKeyPair({
    bool isExtractable = true,
    bool allowSign = true,
  }) async {
    return BrowserEcKeyPair.generate(
      keyPairType: keyPairType,
      isExtractable: isExtractable,
      allowSign: allowSign,
      allowDeriveBits: true,
    );
  }

  @override
  Future<EcKeyPair> newKeyPairFromSeed(List<int> seed) {
    throw UnimplementedError();
  }

  @override
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  }) async {
    if (keyPair is! EcKeyPair) {
      throw ArgumentError.value(
        keyPair,
        'localKeyPair',
        'Should be an instance of EcKeyPair, not: $keyPair',
      );
    }
    final jsPrivateKeyFuture = BrowserEcKeyPair.from(
      keyPair,
      isExtractable: false,
      allowSign: false,
      allowDeriveBits: true,
    );
    final jsPublicKeyFuture = jsPublicKeyFrom(
      remotePublicKey,
      webCryptoCurve: keyPairType.webCryptoCurve!,
    );
    final jsPrivateKey = await jsPrivateKeyFuture;
    final jsPublicKey = await jsPublicKeyFuture;
    try {
      final derivedBytes = await web_crypto.deriveBits(
        web_crypto.DeriveParamsWhenPublicKey(
          name: 'ECDH'.toJS,
          public: jsPublicKey,
        ).jsObject,
        jsPrivateKey.jsPrivateKeyForEcdh!,
        (8 * length).toJS,
      );
      return SecretKey(derivedBytes);
    } catch (error, stackTrace) {
      throw StateError(
        'Web Cryptography throw an error: $error\n$stackTrace',
      );
    }
  }

  static Future<web_crypto.CryptoKey> jsPublicKeyFrom(
    PublicKey publicKey, {
    required String webCryptoCurve,
  }) async {
    if (publicKey is! EcPublicKey) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'Should be EcPublicKey',
      );
    }
    try {
      return await web_crypto.importKeyWhenJwk(
        web_crypto.Jwk(
          kty: 'EC'.toJS,
          crv: webCryptoCurve.toJS,
          ext: true.toJS,
          key_ops: ['deriveBits'.toJS].toJS,
          x: web_crypto.base64UrlEncode(publicKey.x).toJS,
          y: web_crypto.base64UrlEncode(publicKey.y).toJS,
        ),
        web_crypto.EcKeyImportParams(
          name: 'ECDH'.toJS,
          namedCurve: webCryptoCurve.toJS,
        ).jsObject,
        true.toJS,
        const <JSString>[].toJS,
      );
    } catch (error, stackTrace) {
      throw StateError(
        'Web Cryptography throw an error: $error\n$stackTrace',
      );
    }
  }
}
