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

const SignatureAlgorithm webEcdsaP256Sha256 = _WebEcdsa(
  webCryptoNamedCurve: 'P-256',
  webCryptoHashName: 'SHA-256',
  dartImplementation: dart.dartEcdsaP256Sha256,
);

const SignatureAlgorithm webEcdsaP384Sha256 = _WebEcdsa(
  webCryptoNamedCurve: 'P-384',
  webCryptoHashName: 'SHA-256',
  dartImplementation: dart.dartEcdsaP384Sha256,
);

const SignatureAlgorithm webEcdsaP384Sha384 = _WebEcdsa(
  webCryptoNamedCurve: 'P-384',
  webCryptoHashName: 'SHA-384',
  dartImplementation: dart.dartEcdsaP384Sha384,
);

const SignatureAlgorithm webEcdsaP521Sha256 = _WebEcdsa(
  webCryptoNamedCurve: 'P-521',
  webCryptoHashName: 'SHA-256',
  dartImplementation: dart.dartEcdsaP521Sha256,
);

const SignatureAlgorithm webEcdsaP521Sha512 = _WebEcdsa(
  webCryptoNamedCurve: 'P-521',
  webCryptoHashName: 'SHA-512',
  dartImplementation: dart.dartEcdsaP521Sha512,
);

class _WebEcdsa extends SignatureAlgorithm {
  final String webCryptoNamedCurve;
  final String webCryptoHashName;
  final SignatureAlgorithm dartImplementation;

  @override
  String get name => dartImplementation.name;

  @override
  int get publicKeyLength => dartImplementation.publicKeyLength;

  const _WebEcdsa({
    @required this.webCryptoNamedCurve,
    @required this.webCryptoHashName,
    @required this.dartImplementation,
  });

  @override
  Future<KeyPair> newKeyPair() {
    return _newWebEcKeyPair(webCryptoNamedCurve);
  }

  @override
  KeyPair newKeyPairSync() {
    if (dartImplementation == null) {
      throw UnimplementedError();
    }
    return dartImplementation.newKeyPairSync();
  }

  @override
  Future<Signature> sign(List<int> input, KeyPair keyPair) async {
    final subtle = web_crypto.subtle;
    if (subtle == null) {
      // Very old browser
      return super.sign(input, keyPair);
    }
    final privateBytes = await keyPair.privateKey.extract();
    final n = privateBytes.length ~/ 3;
    final privateKeyJwk = web_crypto.Jwk(
      crv: webCryptoNamedCurve,
      d: _base64UrlEncode(privateBytes.sublist(0, n)),
      ext: false,
      key_ops: const ['sign'],
      kty: 'EC',
      x: _base64UrlEncode(privateBytes.sublist(n, 2 * n)),
      y: _base64UrlEncode(privateBytes.sublist(2 * n)),
    );
    final privateKeyJs = await js.promiseToFuture<web_crypto.CryptoKey>(
      subtle.importKey(
        'jwk',
        privateKeyJwk,
        web_crypto.EcKeyImportParams(
          name: 'ECDSA',
          namedCurve: webCryptoNamedCurve,
        ),
        false,
        const ['sign'],
      ),
    );
    return js
        .promiseToFuture<ByteBuffer>(web_crypto.subtle.sign(
      web_crypto.EcdsaParams(
        name: 'ECDSA',
        hash: webCryptoHashName,
      ),
      privateKeyJs,
      _jsArrayBufferFrom(input),
    ))
        .then((byteBuffer) async {
      return Signature(
        Uint8List.view(byteBuffer),
        publicKey: keyPair.publicKey,
      );
    });
  }

  @override
  Signature signSync(List<int> input, KeyPair keyPair) {
    if (dartImplementation == null) {
      throw UnimplementedError();
    }
    return dartImplementation.signSync(input, keyPair);
  }

  @override
  Future<bool> verify(List<int> input, Signature signature) async {
    final subtle = web_crypto.subtle;
    if (subtle == null) {
      // Very old browser
      return super.verify(input, signature);
    }
    final publicKeyBytes = signature.publicKey.bytes;
    final publicKeyJs = await js.promiseToFuture<web_crypto.CryptoKey>(
      subtle.importKey(
        'raw',
        _jsArrayBufferFrom(publicKeyBytes),
        web_crypto.EcKeyImportParams(
          name: 'ECDSA',
          namedCurve: webCryptoNamedCurve,
        ),
        true,
        const ['verify'],
      ),
    );
    return js.promiseToFuture<bool>(web_crypto.subtle.verify(
      web_crypto.EcdsaParams(
        name: 'ECDSA',
        hash: webCryptoHashName,
      ),
      publicKeyJs,
      _jsArrayBufferFrom(signature.bytes),
      _jsArrayBufferFrom(input),
    ));
  }

  @override
  bool verifySync(List<int> input, Signature signature) {
    if (dartImplementation == null) {
      throw UnimplementedError();
    }
    return dartImplementation.verifySync(input, signature);
  }
}
