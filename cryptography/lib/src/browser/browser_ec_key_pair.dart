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

import '../../cryptography_plus.dart';
import '_javascript_bindings.dart' as web_crypto;

class BrowserEcKeyPair extends KeyPair implements EcKeyPair {
  final web_crypto.CryptoKey? jsPrivateKeyForEcdsa;
  final web_crypto.CryptoKey? jsPublicKeyForEcdsa;
  final web_crypto.CryptoKey? jsPrivateKeyForEcdh;
  final web_crypto.CryptoKey? jsPublicKeyForEcdh;
  final KeyPairType keyPairType;
  final bool isExtractable;
  final bool allowSign;
  final bool allowDeriveBits;
  final EcPublicKey publicKey;

  Future<EcKeyPairData>? _extractFuture;

  BrowserEcKeyPair({
    required this.jsPrivateKeyForEcdsa,
    required this.jsPublicKeyForEcdsa,
    required this.jsPrivateKeyForEcdh,
    required this.jsPublicKeyForEcdh,
    required this.keyPairType,
    required this.isExtractable,
    required this.allowSign,
    required this.allowDeriveBits,
    required this.publicKey,
  });

  @override
  Future<EcKeyPairData> extract() {
    return _extractFuture ??= _extract();
  }

  @override
  Future<EcPublicKey> extractPublicKey() async {
    return publicKey;
  }

  @override
  String toString() {
    return 'BrowserEcKeyPair(\n'
        '  ...,\n'
        '  isExtractable: $isExtractable,\n'
        '  allowSign: $allowSign,\n'
        '  allowDeriveBits $allowDeriveBits\n'
        ')';
  }

  Future<EcKeyPairData> _extract() async {
    final jsKeyPair = jsPrivateKeyForEcdsa ?? jsPrivateKeyForEcdh;
    if (jsKeyPair == null) {
      throw StateError('Key pair is not extractable');
    }
    try {
      final jwk = await web_crypto.exportKeyWhenJwk(
        jsKeyPair,
      );
      return EcKeyPairData(
        type: keyPairType,
        d: web_crypto.base64UrlDecodeUnmodifiable(jwk.d!),
        x: web_crypto.base64UrlDecodeUnmodifiable(jwk.x!),
        y: web_crypto.base64UrlDecodeUnmodifiable(jwk.y!),
      );
    } catch (error, stackTrace) {
      throw StateError(
        'Web Cryptography throw an error: $error\n$stackTrace',
      );
    }
  }

  static Future<BrowserEcKeyPair> from(
    EcKeyPair keyPair, {
    required bool isExtractable,
    required bool allowSign,
    required bool allowDeriveBits,
  }) async {
    if (keyPair is BrowserEcKeyPair) {
      if (isExtractable && !keyPair.isExtractable) {
        throw ArgumentError.value(
          keyPair,
          'keyPair',
          'Key pair is not extractable',
        );
      }
      if (allowSign && !keyPair.allowSign) {
        throw ArgumentError.value(
          keyPair,
          'keyPair',
          'Key pair does not allow signing',
        );
      }
      if (allowDeriveBits && !keyPair.allowDeriveBits) {
        throw ArgumentError.value(
          keyPair,
          'keyPair',
          'Key pair does not allow deriving bits',
        );
      }
      return keyPair;
    }
    final keyPairData = await keyPair.extract();
    return BrowserEcKeyPair.fromParameters(
      keyPairType: keyPairData.type,
      d: Uint8List.fromList(keyPairData.d),
      x: Uint8List.fromList(keyPairData.x),
      y: Uint8List.fromList(keyPairData.y),
      isExtractable: isExtractable,
      allowSign: allowSign,
      allowDeriveBits: allowDeriveBits,
    );
  }

  static Future<BrowserEcKeyPair> fromParameters({
    required KeyPairType keyPairType,
    required Uint8List d,
    required Uint8List x,
    required Uint8List y,
    required bool isExtractable,
    required bool allowSign,
    required bool allowDeriveBits,
  }) async {
    final d_ = web_crypto.base64UrlEncode(d);
    final x_ = web_crypto.base64UrlEncode(x);
    final y_ = web_crypto.base64UrlEncode(y);
    try {
      final webCryptoCurve = keyPairType.webCryptoCurve!;
      web_crypto.CryptoKey? jsPrivateKeyForEcdh;
      web_crypto.CryptoKey? jsPublicKeyForEcdh;
      web_crypto.CryptoKey? jsPrivateKeyForEcdsa;
      web_crypto.CryptoKey? jsPublicKeyForEcdsa;
      final futures = <Future>[];
      if (allowSign) {
        // Private key
        futures.add(web_crypto.importKeyWhenJwk(
          web_crypto.Jwk(
            kty: 'EC',
            crv: webCryptoCurve,
            ext: isExtractable,
            key_ops: const ['sign'],
            d: d_,
            x: x_,
            y: y_,
          ),
          web_crypto.EcKeyImportParams(
            name: 'ECDSA',
            namedCurve: webCryptoCurve,
          ),
          isExtractable,
          const ['sign'],
        ).then((value) {
          jsPrivateKeyForEcdsa = value;
        }));
        // Public key
        futures.add(web_crypto.importKeyWhenJwk(
          web_crypto.Jwk(
            kty: 'EC',
            crv: webCryptoCurve,
            ext: true,
            key_ops: const ['verify'],
            x: x_,
            y: y_,
          ),
          web_crypto.EcKeyImportParams(
            name: 'ECDSA',
            namedCurve: webCryptoCurve,
          ),
          true,
          const [],
        ).then((value) {
          jsPublicKeyForEcdsa = value;
        }));
      }
      if (allowDeriveBits) {
        // Private key
        futures.add(web_crypto.importKeyWhenJwk(
          web_crypto.Jwk(
            kty: 'EC',
            crv: webCryptoCurve,
            ext: isExtractable,
            key_ops: const ['deriveBits'],
            d: d_,
            x: x_,
            y: y_,
          ),
          web_crypto.EcKeyImportParams(
            name: 'ECDH',
            namedCurve: webCryptoCurve,
          ),
          isExtractable,
          const ['deriveBits'],
        ).then((value) {
          jsPrivateKeyForEcdh = value;
        }));
        // Public key
        futures.add(web_crypto.importKeyWhenJwk(
          web_crypto.Jwk(
            kty: 'EC',
            crv: webCryptoCurve,
            ext: true,
            key_ops: const ['deriveBits'],
            x: x_,
            y: y_,
          ),
          web_crypto.EcKeyImportParams(
            name: 'ECDH',
            namedCurve: webCryptoCurve,
          ),
          true,
          const [],
        ).then((value) {
          jsPublicKeyForEcdh = value;
        }));
      }
      await Future.wait(futures);
      return BrowserEcKeyPair(
        jsPrivateKeyForEcdsa: jsPrivateKeyForEcdsa,
        jsPublicKeyForEcdsa: jsPublicKeyForEcdsa,
        jsPrivateKeyForEcdh: jsPrivateKeyForEcdh,
        jsPublicKeyForEcdh: jsPublicKeyForEcdh,
        publicKey: EcPublicKey(
          type: keyPairType,
          x: x,
          y: y,
        ),
        keyPairType: keyPairType,
        isExtractable: isExtractable,
        allowSign: allowSign,
        allowDeriveBits: allowDeriveBits,
      );
    } catch (error, stackTrace) {
      throw StateError(
        'Web Cryptography throw an error: $error\n$stackTrace',
      );
    }
  }

  static Future<BrowserEcKeyPair> generate({
    required KeyPairType keyPairType,
    required bool isExtractable,
    required bool allowSign,
    required bool allowDeriveBits,
  }) async {
    try {
      final jsKey = await web_crypto.generateKeyWhenKeyPair(
        web_crypto.EcKeyGenParams(
          name: 'ECDSA',
          namedCurve: keyPairType.webCryptoCurve!,
        ),
        true,
        ['sign'],
      );
      final jwk = await web_crypto.exportKeyWhenJwk(
        jsKey.privateKey,
      );
      return fromParameters(
        keyPairType: keyPairType,
        d: web_crypto.base64UrlDecodeUnmodifiable(jwk.d!),
        x: web_crypto.base64UrlDecodeUnmodifiable(jwk.x!),
        y: web_crypto.base64UrlDecodeUnmodifiable(jwk.y!),
        isExtractable: isExtractable,
        allowSign: allowSign,
        allowDeriveBits: allowDeriveBits,
      );
    } catch (error, stackTrace) {
      throw StateError(
        'Web Cryptography throw an error: $error\n$stackTrace',
      );
    }
  }
}
