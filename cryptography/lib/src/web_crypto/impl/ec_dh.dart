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

// For avoiding confusion with ECDSA, we have separate caching keys
final _ecdhCachingKeys = {
  'P-256': Object(),
  'P-384': Object(),
  'P-521': Object(),
};

Future<KeyPair> ecdhNewKeyPair({@required String curve}) async {
  // Generate key
  final jsKeyPair = await js.promiseToFuture<web_crypto.CryptoKeyPair>(
    web_crypto.generateKey(
      web_crypto.EcdhParams(
        name: 'ECDH',
        namedCurve: curve,
      ),
      true,
      ['deriveBits'],
    ),
  );

  final privateKeyJs = await js.promiseToFuture<web_crypto.Jwk>(
    web_crypto.exportKey('jwk', jsKeyPair.privateKey),
  );
  final privateKey = EcJwkPrivateKey(
    crv: curve,
    d: _base64UrlDecode(privateKeyJs.d),
    x: _base64UrlDecode(privateKeyJs.x),
    y: _base64UrlDecode(privateKeyJs.y),
  );

  // Get public key.
  final publicKeyByteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.exportKey('raw', jsKeyPair.publicKey),
  );
  final publicKey = PublicKey(
    Uint8List.view(publicKeyByteBuffer),
  );

  final cachingKey = _ecdhCachingKeys[curve];
  if (cachingKey != null) {
    privateKey.cachedValues[cachingKey] = jsKeyPair.privateKey;
    publicKey.cachedValues[cachingKey] = jsKeyPair.publicKey;
  }

  return KeyPair(
    privateKey: privateKey,
    publicKey: publicKey,
  );
}

Future<SecretKey> ecdhSharedSecret({
  @required PrivateKey localPrivateKey,
  @required PublicKey remotePublicKey,
  @required String curve,
  int bits = 256,
}) async {
  final jsPrivateKeyFuture = _ecdhPrivateKeyToJs(
    localPrivateKey,
    curve: curve,
  );
  final jsPublicKeyFuture = _ecdhPublicKeyToJs(
    remotePublicKey,
    curve: curve,
  );
  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.deriveBits(
      web_crypto.EcdhKeyDeriveParams(
        name: 'ECDH',
        public: await jsPublicKeyFuture,
      ),
      await jsPrivateKeyFuture,
      bits,
    ),
  );
  return SecretKey(Uint8List.view(byteBuffer));
}

Future<web_crypto.CryptoKey> _ecdhPrivateKeyToJs(
  PrivateKey privateKey, {
  @required String curve,
}) async {
  final cachingKey = _ecdhCachingKeys[curve];
  if (cachingKey != null) {
    final result = privateKey.cachedValues[cachingKey];
    if (result != null) {
      return result;
    }
  }

  final jwk = await EcJwkPrivateKey.from(privateKey);
  final jsJwk = web_crypto.Jwk(
    crv: curve,
    d: _base64UrlEncode(jwk.d),
    ext: true,
    key_ops: const ['deriveBits'],
    kty: 'EC',
    x: _base64UrlEncode(jwk.x),
    y: _base64UrlEncode(jwk.y),
  );

  final result = js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.importKey(
      'jwk',
      jsJwk,
      web_crypto.EcdhParams(
        name: 'ECDH',
        namedCurve: curve,
      ),
      true,
      const ['deriveBits'],
    ),
  );

  if (cachingKey != null) {
    privateKey.cachedValues[cachingKey] = result;
  }

  return result;
}

Future<web_crypto.CryptoKey> _ecdhPublicKeyToJs(
  PublicKey publicKey, {
  @required String curve,
}) async {
  final cachingKey = _ecdhCachingKeys[curve];
  if (cachingKey != null) {
    final result = publicKey.cachedValues[cachingKey];
    if (result != null) {
      return result;
    }
  }

  final result = js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.importKey(
      'raw',
      _jsArrayBufferFrom(publicKey.bytes),
      web_crypto.EcdhParams(
        name: 'ECDH',
        namedCurve: curve,
      ),
      true,
      const [],
    ),
  );

  if (cachingKey != null) {
    publicKey.cachedValues[cachingKey] = result;
  }

  return result;
}
