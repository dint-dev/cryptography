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

const KeyExchangeAlgorithm webEcdhP256 = _WebEcdh(
  webCryptoNamedCurve: 'P-256',
  dartImplementation: dart.dartEcdhP256,
);

const KeyExchangeAlgorithm webEcdhP384 = _WebEcdh(
  webCryptoNamedCurve: 'P-384',
  dartImplementation: dart.dartEcdhP384,
);

const KeyExchangeAlgorithm webEcdhP521 = _WebEcdh(
  webCryptoNamedCurve: 'P-521',
  dartImplementation: dart.dartEcdhP521,
);

class _WebEcdh extends KeyExchangeAlgorithm {
  final String webCryptoNamedCurve;
  final KeyExchangeAlgorithm dartImplementation;

  const _WebEcdh({
    @required this.webCryptoNamedCurve,
    @required this.dartImplementation,
  }) : assert(dartImplementation != null);

  @override
  String get name => dartImplementation.name;

  @override
  int get publicKeyLength => dartImplementation.publicKeyLength;

  @override
  Future<KeyPair> newKeyPair() {
    return _newWebEcKeyPair(webCryptoNamedCurve);
  }

  @override
  KeyPair newKeyPairSync() {
    return dartImplementation.newKeyPairSync();
  }

  @override
  Future<SecretKey> sharedSecret({
    PrivateKey localPrivateKey,
    PublicKey remotePublicKey,
  }) async {
    final subtle = web_crypto.subtle;
    if (subtle == null) {
      // Very old browser
      return super.sharedSecret(
        localPrivateKey: localPrivateKey,
        remotePublicKey: remotePublicKey,
      );
    }
    final privateBytes = await localPrivateKey.extract();
    final n = privateBytes.length ~/ 3;
    final privateKeyJwk = web_crypto.Jwk(
      crv: webCryptoNamedCurve,
      d: _base64UrlEncode(privateBytes.sublist(0, n)),
      ext: true,
      key_ops: const ['deriveBits'],
      kty: 'EC',
      x: _base64UrlEncode(privateBytes.sublist(n, 2 * n)),
      y: _base64UrlEncode(privateBytes.sublist(2 * n)),
    );
    final privateKeyJs = await js.promiseToFuture<web_crypto.CryptoKey>(
      subtle.importKey(
        'jwk',
        privateKeyJwk,
        web_crypto.EcdhParams(
          name: 'ECDH',
          namedCurve: webCryptoNamedCurve,
        ),
        true,
        const ['deriveBits'],
      ),
    );

    final publicKeyBytes = remotePublicKey.bytes;
    final publicKeyJs = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(publicKeyBytes),
        web_crypto.EcdhParams(
          name: 'ECDH',
          namedCurve: webCryptoNamedCurve,
        ),
        true,
        const [],
      ),
    );

    return js
        .promiseToFuture<ByteBuffer>(web_crypto.subtle.deriveBits(
      web_crypto.EcdhKeyDeriveParams(
        name: 'ECDH',
        public: publicKeyJs,
      ),
      privateKeyJs,
      256,
    ))
        .then((byteBuffer) async {
      return SecretKey(Uint8List.view(byteBuffer));
    });
  }

  @override
  SecretKey sharedSecretSync({
    PrivateKey localPrivateKey,
    PublicKey remotePublicKey,
  }) {
    return dartImplementation.sharedSecretSync(
      localPrivateKey: localPrivateKey,
      remotePublicKey: remotePublicKey,
    );
  }
}
