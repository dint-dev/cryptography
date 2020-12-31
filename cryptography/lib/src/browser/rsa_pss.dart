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

import 'hash.dart';
import 'javascript_bindings.dart' as web_crypto;
import 'javascript_bindings.dart' show base64UrlEncode, base64UrlDecode;

/// RSA-PSS implementation that uses _Web Cryptography API_ in browsers.
///
/// See [BrowserCryptography].
class BrowserRsaPss extends RsaPss {
  static const _webCryptoAlgorithm = 'RSA-PSS';

  final int nonceLengthInBytes;

  @override
  final BrowserHashAlgorithmMixin hashAlgorithm;

  const BrowserRsaPss(
    this.hashAlgorithm, {
    this.nonceLengthInBytes = 16,
  }) : super.constructor();

  String get webCryptoHash {
    final h = hashAlgorithm;
    if (h is Sha1) {
      return 'SHA-1';
    }
    if (h is Sha256) {
      return 'SHA-256';
    }
    if (h is Sha384) {
      return 'SHA-384';
    }
    if (h is Sha512) {
      return 'SHA-512';
    }
    throw StateError(
      'Hash function not supported by Web Cryptography API: $hashAlgorithm',
    );
  }

  @override
  Future<RsaKeyPair> newKeyPair({
    int modulusLength = RsaPss.defaultModulusLength,
    List<int> publicExponent = RsaPss.defaultPublicExponent,
  }) async {
    // Generate CryptoKeyPair
    final jsCryptoKeyPair = await js.promiseToFuture<web_crypto.CryptoKeyPair>(
        web_crypto.generateKey(
      web_crypto.RsaHashedKeyGenParams(
        name: _webCryptoAlgorithm,
        modulusLength: modulusLength,
        publicExponent: Uint8List.fromList(publicExponent),
        hash: webCryptoHash,
      ),
      true,
      ['sign', 'verify'],
    ));
    return _BrowserRsaKeyPair(
      jsCryptoKeyPair,
      webCryptoAlgorithm: _webCryptoAlgorithm,
      webCryptoHash: webCryptoHash,
    );
  }

  @override
  Future<Signature> sign(
    List<int> message, {
    required KeyPair keyPair,
  }) async {
    keyPair = await keyPair.extract();
    if (keyPair is! RsaKeyPair) {
      throw ArgumentError.value(
        keyPair,
        'keyPair',
        'Should be an instance of RsaKeyPair',
      );
    }
    final publicKeyFuture = keyPair.extractPublicKey();
    final jsCryptoKey = await _jsCryptoKeyFromRsaKeyPair(
      keyPair,
      webCryptoAlgorithm: _webCryptoAlgorithm,
      webCryptoHash: webCryptoHash,
    );
    final byteBuffer = await js.promiseToFuture(web_crypto.sign(
      web_crypto.RsaPssParams(
        name: _webCryptoAlgorithm,
        saltLength: nonceLengthInBytes,
      ),
      jsCryptoKey,
      web_crypto.jsArrayBufferFrom(message),
    ));
    return Signature(
      List<int>.unmodifiable(
        Uint8List.view(byteBuffer),
      ),
      publicKey: await publicKeyFuture,
    );
  }

  @override
  Future<bool> verify(
    List<int> message, {
    required Signature signature,
  }) async {
    final publicKey = signature.publicKey;
    if (publicKey is! RsaPublicKey) {
      throw ArgumentError.value(
        signature,
        'signature',
        'Public key should be an instance of RsaPublicKey, not: $publicKey',
      );
    }
    final jsCryptoKey = await _jsCryptoKeyFromRsaPublicKey(
      signature.publicKey,
      webCryptoAlgorithm: _webCryptoAlgorithm,
      webCryptoHash: webCryptoHash,
    );
    return js.promiseToFuture<bool>(web_crypto.verify(
      web_crypto.RsaPssParams(
        name: _webCryptoAlgorithm,
        saltLength: nonceLengthInBytes,
      ),
      jsCryptoKey,
      web_crypto.jsArrayBufferFrom(signature.bytes),
      web_crypto.jsArrayBufferFrom(message),
    ));
  }

  Future<web_crypto.CryptoKey> _jsCryptoKeyFromRsaKeyPair(
    KeyPair keyPair, {
    required String webCryptoAlgorithm,
    required String webCryptoHash,
  }) async {
    if (keyPair is _BrowserRsaKeyPair &&
        keyPair.webCryptoAlgorithm == webCryptoAlgorithm &&
        keyPair.webCryptoHash == webCryptoHash) {
      return keyPair.jsCryptoKeyPair.privateKey;
    }
    final keyPairData = await keyPair.extract() as RsaKeyPairData;
    if (!KeyPairType.rsa.isValidKeyPairData(keyPairData)) {
      throw ArgumentError.value(
        keyPair,
        'keyPair',
      );
    }
    // Import JWK key
    return js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.importKey(
        'jwk',
        web_crypto.Jwk(
          kty: 'RSA',
          n: base64UrlEncode(keyPairData.n),
          e: base64UrlEncode(keyPairData.e),
          p: base64UrlEncode(keyPairData.p),
          d: base64UrlEncode(keyPairData.d),
          q: base64UrlEncode(keyPairData.q),
          dp: base64UrlEncode(keyPairData.dp!),
          dq: base64UrlEncode(keyPairData.dq!),
          qi: base64UrlEncode(keyPairData.qi!),
        ),
        web_crypto.RsaHashedImportParams(
          name: webCryptoAlgorithm,
          hash: webCryptoHash,
        ),
        false,
        const ['sign'],
      ),
    );
  }

  Future<web_crypto.CryptoKey> _jsCryptoKeyFromRsaPublicKey(
    PublicKey publicKey, {
    required String webCryptoAlgorithm,
    required String webCryptoHash,
  }) async {
    if (publicKey is _BrowserRsaPublicKey &&
        webCryptoAlgorithm == publicKey.webCryptoAlgorithm &&
        webCryptoHash == publicKey.webCryptoHash) {
      return publicKey.jsCryptoKey;
    }
    if (publicKey is! RsaPublicKey) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'Should be RsaPublicKey',
      );
    }
    return js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.importKey(
        'jwk',
        web_crypto.Jwk(
          kty: 'RSA',
          n: base64UrlEncode(publicKey.n),
          e: base64UrlEncode(publicKey.e),
        ),
        web_crypto.RsaHashedImportParams(
          name: webCryptoAlgorithm,
          hash: webCryptoHash,
        ),
        false,
        const ['verify'],
      ),
    );
  }
}

class _BrowserRsaKeyPair extends KeyPair implements RsaKeyPair {
  final web_crypto.CryptoKeyPair jsCryptoKeyPair;
  final String webCryptoAlgorithm;
  final String webCryptoHash;

  _BrowserRsaKeyPair(
    this.jsCryptoKeyPair, {
    required this.webCryptoAlgorithm,
    required this.webCryptoHash,
  });

  @override
  Future<RsaKeyPairData> extract() async {
    final jsJwk = await js.promiseToFuture<web_crypto.Jwk>(
      web_crypto.exportKey('jwk', jsCryptoKeyPair.privateKey),
    );
    return RsaKeyPairData(
      n: List<int>.unmodifiable(base64UrlDecode(jsJwk.n!)!),
      e: List<int>.unmodifiable(base64UrlDecode(jsJwk.e!)!),
      d: List<int>.unmodifiable(base64UrlDecode(jsJwk.d!)!),
      p: List<int>.unmodifiable(base64UrlDecode(jsJwk.p!)!),
      q: List<int>.unmodifiable(base64UrlDecode(jsJwk.q!)!),
      dp: List<int>.unmodifiable(base64UrlDecode(jsJwk.dp!)!),
      dq: List<int>.unmodifiable(base64UrlDecode(jsJwk.dq!)!),
      qi: List<int>.unmodifiable(base64UrlDecode(jsJwk.qi!)!),
    );
  }

  @override
  Future<RsaPublicKey> extractPublicKey() async {
    final jsJwk = await js.promiseToFuture<web_crypto.Jwk>(
      web_crypto.exportKey('jwk', jsCryptoKeyPair.publicKey),
    );
    return _BrowserRsaPublicKey(
      jsCryptoKey: jsCryptoKeyPair.publicKey,
      webCryptoAlgorithm: webCryptoAlgorithm,
      webCryptoHash: webCryptoHash,
      n: List<int>.unmodifiable(base64UrlDecode(jsJwk.n!)!),
      e: List<int>.unmodifiable(base64UrlDecode(jsJwk.e!)!),
    );
  }
}

class _BrowserRsaPublicKey extends RsaPublicKey {
  final web_crypto.CryptoKey jsCryptoKey;
  final String webCryptoAlgorithm;
  final String webCryptoHash;

  _BrowserRsaPublicKey({
    required this.jsCryptoKey,
    required this.webCryptoAlgorithm,
    required this.webCryptoHash,
    required List<int> n,
    required List<int> e,
  }) : super(n: n, e: e);
}
