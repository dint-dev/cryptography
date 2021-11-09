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
import 'package:cryptography/src/browser/hash.dart';
import 'package:js/js_util.dart' as js;

import 'javascript_bindings.dart' as web_crypto;

Future<web_crypto.CryptoKey> jsCryptoKeyFromEcdsaKeyPair(
    EcKeyPair keyPair) async {
  final keyPairData = await keyPair.extract();
  final webCryptoAlgorithm = const <KeyPairType, String>{
    KeyPairType.p256: 'P-256',
    KeyPairType.p384: 'P-384',
    KeyPairType.p521: 'P-521',
  }[keyPairData.type];
  if (webCryptoAlgorithm == null) {
    throw ArgumentError.value(
      keyPair,
      'keyPair',
    );
  }
  if (keyPair is _BrowserEcdsaKeyPair &&
      keyPairData.type == keyPair.keyPairType) {
    return keyPair.jsCryptoKeyPair.privateKey;
  }
  final type = keyPairData.type;
  final crv = {
    KeyPairType.p256: 'P-256',
    KeyPairType.p384: 'P-384',
    KeyPairType.p521: 'P-521',
  }[type];
  if (crv == null) {
    throw ArgumentError.value(
      keyPair,
      'keyPair',
      'Invalid key type: $type',
    );
  }
  final jsJwk = web_crypto.Jwk(
    kty: 'EC',
    crv: crv,
    ext: true,
    key_ops: const ['sign'],
    d: web_crypto.base64UrlEncode(keyPairData.d),
    x: web_crypto.base64UrlEncode(keyPairData.x),
    y: web_crypto.base64UrlEncode(keyPairData.y),
  );
  try {
    return await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.importKey(
        'jwk',
        jsJwk,
        web_crypto.EcKeyImportParams(
          name: 'ECDSA',
          namedCurve: webCryptoAlgorithm,
        ),
        true,
        const ['sign'],
      ),
    );
  } catch (error) {
    throw StateError(
      'Web Cryptography returned an error when importing ECDH key pair: $error',
    );
  }
}

Future<web_crypto.CryptoKey> jsCryptoKeyFromEcdsaPublicKey(
  PublicKey publicKey, {
  required String webCryptoCurve,
  required String webCryptoHash,
}) async {
  if (publicKey is! EcPublicKey) {
    throw ArgumentError.value(
      publicKey,
      'publicKey',
      'Should be EcPublicKey',
    );
  }
  return js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.importKey(
      'jwk',
      web_crypto.Jwk(
        kty: 'EC',
        crv: webCryptoCurve,
        ext: true,
        key_ops: const ['verify'],
        x: web_crypto.base64UrlEncode(publicKey.x),
        y: web_crypto.base64UrlEncode(publicKey.y),
      ),
      web_crypto.EcKeyImportParams(
        name: 'ECDSA',
        namedCurve: webCryptoCurve,
      ),
      true,
      const ['verify'],
    ),
  );
}

class BrowserEcdsa extends Ecdsa {
  @override
  final BrowserHashAlgorithmMixin hashAlgorithm;

  @override
  final KeyPairType keyPairType;

  BrowserEcdsa.p256(BrowserHashAlgorithmMixin hashAlgorithm)
      : this._(KeyPairType.p256, hashAlgorithm);

  BrowserEcdsa.p384(BrowserHashAlgorithmMixin hashAlgorithm)
      : this._(KeyPairType.p384, hashAlgorithm);

  BrowserEcdsa.p521(BrowserHashAlgorithmMixin hashAlgorithm)
      : this._(KeyPairType.p521, hashAlgorithm);

  BrowserEcdsa._(this.keyPairType, this.hashAlgorithm) : super.constructor();

  @override
  Future<EcKeyPair> newKeyPair() async {
    final jsCryptoKeyPair = await js.promiseToFuture<web_crypto.CryptoKeyPair>(
      web_crypto.generateKey(
        web_crypto.EcKeyGenParams(
          name: 'ECDSA',
          namedCurve: keyPairType.webCryptoCurve!,
        ),
        true,
        const ['sign', 'verify'],
      ),
    );
    return _BrowserEcdsaKeyPair._(
      jsCryptoKeyPair,
      keyPairType,
    );
  }

  @override
  Future<EcKeyPair> newKeyPairFromSeed(List<int> seed) {
    throw UnimplementedError();
  }

  @override
  Future<Signature> sign(List<int> message, {required KeyPair keyPair}) async {
    keyPair = await keyPair.extract();
    if (keyPair is! EcKeyPair) {
      throw ArgumentError.value(
        keyPair,
        'keyPair',
        'Should be an instance of EcKeyPair',
      );
    }
    final publicKeyFuture = keyPair.extractPublicKey();
    final jsSecretKey = await jsCryptoKeyFromEcdsaKeyPair(
      keyPair,
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.sign(
        web_crypto.EcdsaParams(
          name: 'ECDSA',
          hash: hashAlgorithm.webCryptoName,
        ),
        jsSecretKey,
        web_crypto.jsArrayBufferFrom(message),
      ),
    );
    return Signature(
      Uint8List.view(byteBuffer),
      publicKey: await publicKeyFuture,
    );
  }

  @override
  Future<bool> verify(
    List<int> message, {
    required Signature signature,
  }) async {
    final publicKey = signature.publicKey;
    if (publicKey is! EcPublicKey) {
      throw ArgumentError.value(
        signature,
        'signature',
        'Public key should be an instance of EcPublicKey, not: $publicKey',
      );
    }
    final jsCryptoKey = await jsCryptoKeyFromEcdsaPublicKey(
      signature.publicKey,
      webCryptoCurve: keyPairType.webCryptoCurve!,
      webCryptoHash: hashAlgorithm.webCryptoName,
    );
    return js.promiseToFuture<bool>(web_crypto.verify(
      web_crypto.EcdsaParams(
        name: 'ECDSA',
        hash: hashAlgorithm.webCryptoName,
      ),
      jsCryptoKey,
      web_crypto.jsArrayBufferFrom(signature.bytes),
      web_crypto.jsArrayBufferFrom(message),
    ));
  }
}

class _BrowserEcdsaKeyPair extends KeyPair implements EcKeyPair {
  final web_crypto.CryptoKeyPair jsCryptoKeyPair;
  final KeyPairType keyPairType;
  Future<EcKeyPairData>? _keyPairData;
  Future<EcPublicKey>? _publicKey;

  _BrowserEcdsaKeyPair._(
    this.jsCryptoKeyPair,
    this.keyPairType,
  );

  @override
  Future<EcKeyPairData> extract() {
    return _keyPairData ??= js
        .promiseToFuture<web_crypto.Jwk>(
      web_crypto.exportKey(
        'jwk',
        jsCryptoKeyPair.privateKey,
      ),
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
          'Web Cryptography returned an error when exporting ECDSA key pair: $error',
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
          'Web Cryptography returned an error when exporting ECDSA public key: $error',
        );
      },
    );
  }
}
