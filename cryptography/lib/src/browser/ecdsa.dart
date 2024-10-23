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

import 'package:cryptography_plus/cryptography_plus.dart';

import '_javascript_bindings.dart' as web_crypto;
import 'browser_ec_key_pair.dart';
import 'hash.dart';

class BrowserEcdsa extends Ecdsa {
  @override
  final HashAlgorithm hashAlgorithm;

  @override
  final KeyPairType keyPairType;

  BrowserEcdsa({
    required this.keyPairType,
    required this.hashAlgorithm,
  }) : super.constructor();

  BrowserEcdsa.p256(
    HashAlgorithm hashAlgorithm, {
    Random? random,
  }) : this(
          keyPairType: KeyPairType.p256,
          hashAlgorithm: hashAlgorithm,
        );

  BrowserEcdsa.p384(
    HashAlgorithm hashAlgorithm, {
    Random? random,
  }) : this(
          keyPairType: KeyPairType.p384,
          hashAlgorithm: hashAlgorithm,
        );

  BrowserEcdsa.p521(
    HashAlgorithm hashAlgorithm, {
    Random? random,
  }) : this(
          keyPairType: KeyPairType.p521,
          hashAlgorithm: hashAlgorithm,
        );

  @override
  Future<EcKeyPair> newKeyPair({
    bool isExtractable = true,
    bool allowDeriveBits = true,
  }) async {
    return BrowserEcKeyPair.generate(
      keyPairType: keyPairType,
      isExtractable: isExtractable,
      allowDeriveBits: allowDeriveBits,
      allowSign: true,
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
    final browserEcKeyPair = await BrowserEcKeyPair.from(
      keyPair,
      isExtractable: false,
      allowSign: true,
      allowDeriveBits: true,
    );
    final jsCryptoKey = browserEcKeyPair.jsPrivateKeyForEcdsa!;
    final byteBuffer = await web_crypto.sign(
      web_crypto.EcdsaParams(
        name: 'ECDSA',
        hash: BrowserHashAlgorithmMixin.hashAlgorithmNameFor(
          hashAlgorithm,
        )!,
      ),
      jsCryptoKey,
      web_crypto.jsArrayBufferFrom(message),
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
    final hashAlgorithmName = BrowserHashAlgorithmMixin.hashAlgorithmNameFor(
      hashAlgorithm,
    )!;
    final jsCryptoKey = await jsPublicKeyFrom(
      signature.publicKey,
      webCryptoCurve: keyPairType.webCryptoCurve!,
      webCryptoHash: hashAlgorithmName,
    );
    return await web_crypto.verify(
      web_crypto.EcdsaParams(
        name: 'ECDSA',
        hash: hashAlgorithmName,
      ),
      jsCryptoKey,
      web_crypto.jsArrayBufferFrom(signature.bytes),
      web_crypto.jsArrayBufferFrom(message),
    );
  }

  static Future<web_crypto.CryptoKey> jsPublicKeyFrom(
    PublicKey publicKey, {
    required String webCryptoCurve,
    required String webCryptoHash,
  }) async {
    if (publicKey is! EcPublicKey) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'Should be $EcPublicKey',
      );
    }
    return web_crypto.importKeyWhenJwk(
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
      false,
      const ['verify'],
    );
  }
}
