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

// For avoiding confusion with ECDH, we have separate caching keys
final _ecdsaCachingKeys = {
  'P-256': Object(),
  'P-384': Object(),
  'P-521': Object(),
};

Future<KeyPair> ecdsaNewKeyPair({@required String curve}) async {
  // Generate key
  final jsKeyPair = await js.promiseToFuture<web_crypto.CryptoKeyPair>(
    web_crypto.generateKey(
      web_crypto.EcdhParams(
        name: 'ECDSA',
        namedCurve: curve,
      ),
      true,
      ['sign', 'verify'],
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
  final publicKeyBytes = Uint8List.view(publicKeyByteBuffer);
  final publicKey = PublicKey(publicKeyBytes);

  final cachingKey = _ecdsaCachingKeys[curve];
  if (cachingKey != null) {
    privateKey.cachedValues[cachingKey] = jsKeyPair.privateKey;
    publicKey.cachedValues[cachingKey] = jsKeyPair.publicKey;
  }

  return KeyPair(
    privateKey: privateKey,
    publicKey: publicKey,
  );
}

Future<Signature> ecdsaSign(
  List<int> input,
  KeyPair keyPair, {
  @required String namedCurve,
  @required String hashName,
}) async {
  final jsPrivateKey = await _ecdsaPrivateKeyToJs(
    keyPair.privateKey,
    curve: namedCurve,
  );
  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.sign(
      web_crypto.EcdsaParams(
        name: 'ECDSA',
        hash: hashName,
      ),
      jsPrivateKey,
      _jsArrayBufferFrom(input),
    ),
  );
  return Signature(
    Uint8List.view(byteBuffer),
    publicKey: keyPair.publicKey,
  );
}

Future<bool> ecdsaVerify(
  List<int> input,
  Signature signature, {
  @required String namedCurve,
  @required String hashName,
}) async {
  final publicKeyJs = await _ecdsaPublicKeyToJs(
    signature.publicKey,
    curve: namedCurve,
  );
  return js.promiseToFuture<bool>(web_crypto.verify(
    web_crypto.EcdsaParams(
      name: 'ECDSA',
      hash: hashName,
    ),
    publicKeyJs,
    _jsArrayBufferFrom(signature.bytes),
    _jsArrayBufferFrom(input),
  ));
}

List<int> _base64UrlDecode(String s) {
  switch (s.length % 4) {
    case 1:
      return base64Url.decode(s + '===');
    case 2:
      return base64Url.decode(s + '==');
    case 3:
      return base64Url.decode(s + '=');
    default:
      return base64Url.decode(s);
  }
}

String _base64UrlEncode(List<int> data) {
  var s = base64Url.encode(data);
  // Remove trailing '=' characters
  var length = s.length;
  while (s.startsWith('=', length - 1)) {
    length--;
  }
  return s.substring(0, length);
}

Future<web_crypto.CryptoKey> _ecdsaPrivateKeyToJs(
  PrivateKey privateKey, {
  @required String curve,
}) async {
  final cachingKey = _ecdsaCachingKeys[curve];
  if (cachingKey != null) {
    final result = privateKey.cachedValues[cachingKey];
    if (result != null) {
      return result;
    }
  }

  final jwkPrivateKey = await EcJwkPrivateKey.from(privateKey);
  final result = js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.importKey(
      'jwk',
      web_crypto.Jwk(
        crv: curve,
        d: _base64UrlEncode(jwkPrivateKey.d),
        ext: false,
        key_ops: const ['sign'],
        kty: 'EC',
        x: _base64UrlEncode(jwkPrivateKey.x),
        y: _base64UrlEncode(jwkPrivateKey.y),
      ),
      web_crypto.EcKeyImportParams(
        name: 'ECDSA',
        namedCurve: curve,
      ),
      false,
      const ['sign'],
    ),
  );

  if (cachingKey != null) {
    privateKey.cachedValues[cachingKey] = result;
  }

  return result;
}

Future<web_crypto.CryptoKey> _ecdsaPublicKeyToJs(
  PublicKey publicKey, {
  @required String curve,
}) async {
  final cachingKey = _ecdsaCachingKeys[curve];
  if (cachingKey != null) {
    final result = publicKey.cachedValues[cachingKey];
    if (result != null) {
      return result;
    }
  }

  final result = await js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.importKey(
      'raw',
      _jsArrayBufferFrom(publicKey.bytes),
      web_crypto.EcKeyImportParams(
        name: 'ECDSA',
        namedCurve: curve,
      ),
      true,
      const ['verify'],
    ),
  );

  if (cachingKey != null) {
    publicKey.cachedValues[cachingKey] = result;
  }

  return result;
}
