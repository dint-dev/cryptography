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

import 'javascript_bindings.dart' as web_crypto;

Future<web_crypto.CryptoKey> jsCryptoKeyFromEcdhKeyPair(
  EcKeyPair keyPair, {
  required String webCryptoCurve,
}) async {
  if (keyPair is _BrowserEcdhKeyPair) {
    return keyPair.jsCryptoKeyPair.privateKey;
  }
  final keyPairData = await keyPair.extract();
  if (keyPairData is! EcKeyPairData) {
    throw ArgumentError.value(
      keyPair,
      'keyPair',
    );
  }
  try {
    return await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.importKey(
        'jwk',
        web_crypto.Jwk(
          kty: 'EC',
          crv: webCryptoCurve,
          ext: true,
          key_ops: const ['deriveBits'],
          d: web_crypto.base64UrlEncode(keyPairData.d),
          x: web_crypto.base64UrlEncode(keyPairData.x),
          y: web_crypto.base64UrlEncode(keyPairData.y),
        ),
        web_crypto.EcKeyImportParams(
          name: 'ECDH',
          namedCurve: webCryptoCurve,
        ),
        true,
        const ['deriveBits'],
      ),
    );
  } catch (error) {
    throw StateError(
      'Web Cryptography returned an error when importing ECDH key pair: $error',
    );
  }
}

Future<web_crypto.CryptoKey> jsCryptoKeyFromEcdhPublicKey(
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
    return js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.importKey(
        'jwk',
        web_crypto.Jwk(
          kty: 'EC',
          crv: webCryptoCurve,
          ext: true,
          key_ops: const ['deriveBits'],
          x: web_crypto.base64UrlEncode(publicKey.x),
          y: web_crypto.base64UrlEncode(publicKey.y),
        ),
        web_crypto.EcKeyImportParams(
          name: 'ECDH',
          namedCurve: webCryptoCurve,
        ),
        true,
        const [],
      ),
    );
  } catch (error) {
    throw StateError(
        'Web Cryptography returned an error when importing ECDH public key: $error');
  }
}

class BrowserEcdh extends Ecdh {
  final int length;

  @override
  final KeyPairType keyPairType;

  /// ECDH with P-256.
  factory BrowserEcdh.p256({required int length}) {
    return BrowserEcdh._(
      KeyPairType.p256,
      length: length,
    );
  }

  /// ECDH with P-384.
  factory BrowserEcdh.p384({required int length}) {
    return BrowserEcdh._(
      KeyPairType.p384,
      length: length,
    );
  }

  /// ECDH with P-521.
  factory BrowserEcdh.p521({required int length}) {
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
  Future<EcKeyPair> newKeyPair() async {
    try {
      final jsCryptoKeyPair =
          await js.promiseToFuture<web_crypto.CryptoKeyPair>(
        web_crypto.generateKey(
          web_crypto.EcdhParams(
            name: 'ECDH',
            namedCurve: keyPairType.webCryptoCurve!,
          ),
          true,
          const ['deriveBits'],
        ),
      );
      return _BrowserEcdhKeyPair(
        jsCryptoKeyPair,
        keyPairType,
      );
    } catch (error) {
      throw StateError(
        'Web Cryptography returned an error when generating ECDH key pair: $error',
      );
    }
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
    keyPair = await keyPair.extract();
    if (keyPair is! EcKeyPair) {
      throw ArgumentError.value(
        keyPair,
        'localKeyPair',
        'Should be an instance of EcKeyPair, not: $keyPair',
      );
    }
    final jsPrivateKeyFuture = jsCryptoKeyFromEcdhKeyPair(
      keyPair,
      webCryptoCurve: keyPairType.webCryptoCurve!,
    );
    final jsPublicKeyFuture = jsCryptoKeyFromEcdhPublicKey(
      remotePublicKey,
      webCryptoCurve: keyPairType.webCryptoCurve!,
    );
    final jsPrivateKey = await jsPrivateKeyFuture;
    final jsPublicKey = await jsPublicKeyFuture;
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.deriveBits(
        web_crypto.EcdhKeyDeriveParams(
          name: 'ECDH',
          public: jsPublicKey,
        ),
        jsPrivateKey,
        8 * length,
      ),
    );
    return SecretKey(Uint8List.view(byteBuffer));
  }
}

class _BrowserEcdhKeyPair extends KeyPair implements EcKeyPair {
  final web_crypto.CryptoKeyPair jsCryptoKeyPair;
  final KeyPairType keyPairType;
  Future<EcKeyPairData>? _keyPairData;
  Future<EcPublicKey>? _publicKey;

  _BrowserEcdhKeyPair(this.jsCryptoKeyPair, this.keyPairType);

  @override
  Future<EcKeyPairData> extract() {
    return _keyPairData ??= js
        .promiseToFuture<web_crypto.Jwk>(
      web_crypto.exportKey('jwk', jsCryptoKeyPair.privateKey),
    )
        .then(
      (jwk) => EcKeyPairData(
        type: keyPairType,
        d: List<int>.unmodifiable(web_crypto.base64UrlDecode(jwk.d!)!),
        x: List<int>.unmodifiable(web_crypto.base64UrlDecode(jwk.x!)!),
        y: List<int>.unmodifiable(web_crypto.base64UrlDecode(jwk.y!)!),
      ),
      onError: (error) {
        throw StateError(
          'Web Cryptography returned an error when exporting ECDH key pair: $error',
        );
      },
    );
  }

  @override
  Future<EcPublicKey> extractPublicKey() {
    return _publicKey ??= js
        .promiseToFuture<web_crypto.Jwk>(
      web_crypto.exportKey('jwk', jsCryptoKeyPair.publicKey),
    )
        .then(
      (jwk) => EcPublicKey(
        type: keyPairType,
        x: web_crypto.base64UrlDecode(jwk.x!)!,
        y: web_crypto.base64UrlDecode(jwk.y!)!,
      ),
      onError: (error) {
        throw StateError(
          'Web Cryptography returned an error when exporting ECDH public key: $error',
        );
      },
    );
  }
}
