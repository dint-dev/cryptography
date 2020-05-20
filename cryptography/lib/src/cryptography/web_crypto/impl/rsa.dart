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

part of web_crypto;

abstract class WebRsaSignatureAlgorithm extends SignatureAlgorithm {
  final HashAlgorithm hash;
  final int defaultModulusLength;
  final List<int> defaultPublicExponent;

  WebRsaSignatureAlgorithm(
    this.hash, {
    this.defaultModulusLength = 4096,
    this.defaultPublicExponent = const <int>[0x01, 0x00, 0x01],
  });

  @override
  int get publicKeyLength => null;

  String get webCryptoHashName {
    switch (hash.name) {
      case 'sha256':
        return 'SHA-256';
      case 'sha384':
        return 'SHA-384';
      case 'sha512':
        return 'SHA-512';
      default:
        return null;
    }
  }

  String get webCryptoName;

  @override
  Future<KeyPair> newKeyPair() async {
    // Generate CryptoKeyPair
    final jsCryptoKeyPair = await js.promiseToFuture<web_crypto.CryptoKeyPair>(
        web_crypto.subtle.generateKey(
      web_crypto.RsaHashedKeyGenParams(
        name: webCryptoName,
        modulusLength: defaultModulusLength,
        publicExponent: Uint8List.fromList(defaultPublicExponent),
        hash: webCryptoHashName,
      ),
      true,
      ['sign'],
    ));

    // Export to JWK
    final jsJwk = await js.promiseToFuture<web_crypto.Jwk>(
      web_crypto.subtle.exportKey('jwk', jsCryptoKeyPair.privateKey),
    );

    // Construct a keys
    final privateKey = RsaJwkPrivateKey(
      n: _base64UrlDecode(jsJwk.n),
      e: _base64UrlDecode(jsJwk.e),
      d: _base64UrlDecode(jsJwk.d),
      p: _base64UrlDecode(jsJwk.p),
      q: _base64UrlDecode(jsJwk.q),
      dp: _base64UrlDecode(jsJwk.dp),
      dq: _base64UrlDecode(jsJwk.dq),
      qi: _base64UrlDecode(jsJwk.qi),
    );
    final publicKey = privateKey.toPublicKey();

    // Cache Web Cryptography keys
    privateKey.cachedValues[this] = jsCryptoKeyPair.privateKey;
    publicKey.cachedValues[this] = jsCryptoKeyPair.publicKey;

    // Return a key pair
    return KeyPair(
      privateKey: privateKey,
      publicKey: publicKey,
    );
  }

  @override
  KeyPair newKeyPairSync() {
    throw UnimplementedError(
      'RSA is only supported in browsers. Synchronous methods are not supported.',
    );
  }

  @override
  Signature signSync(List<int> input, KeyPair keyPair) {
    throw UnimplementedError(
      'RSA is only supported in browsers. Synchronous methods are not supported.',
    );
  }

  @override
  bool verifySync(List<int> input, Signature signature) {
    throw UnimplementedError(
      'RSA is only supported in browsers. Synchronous methods are not supported.',
    );
  }

  Future<web_crypto.CryptoKey> _getCryptoKeyFromPrivateKey(
      PrivateKey privateKey) async {
    // Is it cached?
    final cachedValue = privateKey.cachedValues[this];
    if (cachedValue != null) {
      return cachedValue;
    }

    // Import JWK key
    final jwkPrivateKey = privateKey as RsaJwkPrivateKey;
    final jsCryptoKey = js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'jwk',
        web_crypto.Jwk(
          kty: 'RSA',
          n: _base64UrlEncode(jwkPrivateKey.n),
          e: _base64UrlEncode(jwkPrivateKey.e),
          p: _base64UrlEncode(jwkPrivateKey.p),
          d: _base64UrlEncode(jwkPrivateKey.d),
          q: _base64UrlEncode(jwkPrivateKey.q),
          dp: _base64UrlEncode(jwkPrivateKey.dp),
          dq: _base64UrlEncode(jwkPrivateKey.dq),
          qi: _base64UrlEncode(jwkPrivateKey.qi),
        ),
        web_crypto.RsaHashedImportParams(
          name: webCryptoName,
          hash: 'SHA-256',
        ),
        false,
        const ['sign'],
      ),
    );

    // Cache
    privateKey.cachedValues[this] = jsCryptoKey;

    return jsCryptoKey;
  }

  Future<web_crypto.CryptoKey> _getCryptoKeyFromPublicKey(
      PublicKey publicKey) async {
    // Is it cached?
    final cachedValue = publicKey.cachedValues[this];
    if (cachedValue != null) {
      return cachedValue;
    }

    // Import JWK key
    final jwkPrivateKey = publicKey as RsaJwkPublicKey;
    final jsCryptoKey = js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'jwk',
        web_crypto.Jwk(
          kty: 'RSA',
          n: _base64UrlEncode(jwkPrivateKey.n),
          e: _base64UrlEncode(jwkPrivateKey.e),
        ),
        web_crypto.RsaHashedImportParams(
          name: webCryptoName,
          hash: webCryptoHashName,
        ),
        false,
        const ['verify'],
      ),
    );

    // Cache
    publicKey.cachedValues[this] = jsCryptoKey;

    return jsCryptoKey;
  }
}
