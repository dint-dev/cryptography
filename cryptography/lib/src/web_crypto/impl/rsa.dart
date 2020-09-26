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

@override
Future<KeyPair> rsaNewKeyPairForSigning({
  @required String name,
  @required int modulusLength,
  @required List<int> publicExponent,
  @required String hashName,
}) async {
  ArgumentError.checkNotNull(name);
  ArgumentError.checkNotNull(modulusLength);
  ArgumentError.checkNotNull(publicExponent);
  ArgumentError.checkNotNull(hashName);
  // Generate CryptoKeyPair
  final jsCryptoKeyPair =
      await js.promiseToFuture<web_crypto.CryptoKeyPair>(web_crypto.generateKey(
    web_crypto.RsaHashedKeyGenParams(
      name: name,
      modulusLength: modulusLength,
      publicExponent: Uint8List.fromList(publicExponent),
      hash: hashName,
    ),
    true,
    ['sign', 'verify'],
  ));

  // Export to JWK
  final jsJwk = await js.promiseToFuture<web_crypto.Jwk>(
    web_crypto.exportKey('jwk', jsCryptoKeyPair.privateKey),
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
  privateKey.cachedValues[_webCryptoKeyCachingKey] = jsCryptoKeyPair.privateKey;
  publicKey.cachedValues[_webCryptoKeyCachingKey] = jsCryptoKeyPair.publicKey;

  // Return a key pair
  return KeyPair(
    privateKey: privateKey,
    publicKey: publicKey,
  );
}

Future<Signature> rsaPssSign(
  List<int> message,
  KeyPair keyPair, {
  @required int saltLength,
  @required String hashName,
}) async {
  final byteBuffer = await js.promiseToFuture(web_crypto.sign(
    web_crypto.RsaPssParams(
      name: 'RSA-PSS',
      saltLength: saltLength,
    ),
    await _rsaCryptoKeyFromPrivateKey(
      keyPair.privateKey,
      name: 'RSA-PSS',
      hashName: hashName,
    ),
    _jsArrayBufferFrom(message),
  ));
  return Signature(
    Uint8List.view(byteBuffer),
    publicKey: keyPair.publicKey,
  );
}

Future<bool> rsaPssVerify(
  List<int> input,
  Signature signature, {
  @required int saltLength,
  @required String hashName,
}) async {
  return js.promiseToFuture<bool>(web_crypto.verify(
    web_crypto.RsaPssParams(
      name: 'RSA-PSS',
      saltLength: saltLength,
    ),
    await _rsaCryptoKeyFromPublicKey(
      signature.publicKey,
      name: 'RSA-PSS',
      hashName: hashName,
    ),
    _jsArrayBufferFrom(signature.bytes),
    _jsArrayBufferFrom(input),
  ));
}

Future<Signature> rsaSsaPkcs1v15Sign(
  List<int> input,
  KeyPair keyPair, {
  @required String hashName,
}) async {
  final byteBuffer = await js.promiseToFuture(web_crypto.sign(
    'RSASSA-PKCS1-v1_5',
    await _rsaCryptoKeyFromPrivateKey(
      keyPair.privateKey,
      name: 'RSASSA-PKCS1-v1_5',
      hashName: hashName,
    ),
    _jsArrayBufferFrom(input),
  ));
  return Signature(
    Uint8List.view(byteBuffer),
    publicKey: keyPair.publicKey,
  );
}

Future<bool> rsaSsaPkcs1v15Verify(
  List<int> input,
  Signature signature, {
  @required String hashName,
}) async {
  return js.promiseToFuture<bool>(web_crypto.verify(
    'RSASSA-PKCS1-v1_5',
    await _rsaCryptoKeyFromPublicKey(
      signature.publicKey,
      name: 'RSASSA-PKCS1-v1_5',
      hashName: hashName,
    ),
    _jsArrayBufferFrom(signature.bytes),
    _jsArrayBufferFrom(input),
  ));
}

Future<web_crypto.CryptoKey> _rsaCryptoKeyFromPrivateKey(
  PrivateKey privateKey, {
  @required String name,
  @required String hashName,
}) async {
  // Is it cached?
  final cachedValue = privateKey.cachedValues[_webCryptoKeyCachingKey];
  if (cachedValue != null) {
    return cachedValue;
  }

  // Import JWK key
  final jwkPrivateKey = privateKey as RsaJwkPrivateKey;
  final jsCryptoKey = js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.importKey(
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
        name: name,
        hash: hashName,
      ),
      false,
      const ['sign'],
    ),
  );

  // Cache
  privateKey.cachedValues[_webCryptoKeyCachingKey] = jsCryptoKey;

  return jsCryptoKey;
}

Future<web_crypto.CryptoKey> _rsaCryptoKeyFromPublicKey(
  PublicKey publicKey, {
  @required String name,
  @required String hashName,
}) async {
  // Is it cached?
  final cachedValue = publicKey.cachedValues[_webCryptoKeyCachingKey];
  if (cachedValue != null) {
    return cachedValue;
  }

  // Import JWK key
  final jwkPrivateKey = publicKey as RsaJwkPublicKey;
  final jsCryptoKey = js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.importKey(
      'jwk',
      web_crypto.Jwk(
        kty: 'RSA',
        n: _base64UrlEncode(jwkPrivateKey.n),
        e: _base64UrlEncode(jwkPrivateKey.e),
      ),
      web_crypto.RsaHashedImportParams(
        name: name,
        hash: hashName,
      ),
      false,
      const ['verify'],
    ),
  );

  // Cache
  publicKey.cachedValues[_webCryptoKeyCachingKey] = jsCryptoKey;

  return jsCryptoKey;
}
