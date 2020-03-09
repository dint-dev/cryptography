// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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

import 'dart:async';
import 'dart:convert';
import 'dart:js' as js;
import 'dart:js_util' as js;
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

import 'web_crypto_bindings.dart' as web_crypto;

const _aesKeyGenerator = SecretKeyGenerator(
  validLengths: <int>{16, 24, 32},
  defaultLength: 32,
);

ByteBuffer _jsArrayBufferFrom(List<int> data) {
  return Uint8List.fromList(data).buffer;
}

class WebAesCbcCipher extends Cipher {
  const WebAesCbcCipher();

  @override
  String get name => 'aesCbc';

  @override
  int get nonceLength => 16;

  @override
  SecretKeyGenerator get secretKeyGenerator => _aesKeyGenerator;

  @override
  Future<Uint8List> decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) async {
    if (offset != 0) {
      throw ArgumentError.value(offset, 'offset', 'Should be 0');
    }
    if (nonce == null) {
      throw ArgumentError.notNull('nonce');
    }
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKey.bytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CBC',
          length: 8 * secretKey.bytes.length,
        ),
        true,
        ['decrypt'],
      ),
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.decrypt(
        web_crypto.AesCbcParams(
          name: 'AES-CBC',
          iv: Uint8List.fromList(nonce.bytes.sublist(0, 16)).buffer,
        ),
        cryptoKey,
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError('decryptSync() is unsupported');
  }

  @override
  Future<Uint8List> encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) async {
    if (offset != 0) {
      throw ArgumentError.value(offset, 'offset', 'Should be 0');
    }
    if (nonce == null) {
      throw ArgumentError.notNull('nonce');
    }
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKey.bytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CBC',
          length: 8 * secretKey.bytes.length,
        ),
        true,
        ['encrypt'],
      ),
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.encrypt(
        web_crypto.AesCbcParams(
          name: 'AES-CBC',
          iv: Uint8List.fromList(nonce.bytes.sublist(0, 16)).buffer,
        ),
        cryptoKey,
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }

  @override
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError('encryptSync() is unsupported');
  }
}

class WebAesCtrCipher extends Cipher {
  const WebAesCtrCipher();

  @override
  String get name => 'aesCtr';

  @override
  int get nonceLength => 16;

  @override
  SecretKeyGenerator get secretKeyGenerator => _aesKeyGenerator;

  @override
  Future<Uint8List> decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) async {
    if (offset != 0) {
      throw ArgumentError.value(offset, 'offset', 'Should be 0');
    }
    if (nonce == null) {
      throw ArgumentError.notNull('nonce');
    }
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKey.bytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CTR',
          length: 8 * secretKey.bytes.length,
        ),
        true,
        ['decrypt'],
      ),
    );
    final counter = Uint8List.fromList(nonce.bytes.sublist(0, 16)).buffer;
    ByteData.view(counter)..setUint32(8, 0)..setUint32(12, 0);
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.decrypt(
        web_crypto.AesCtrParams(
          name: 'AES-CTR',
          counter: counter,
          length: 64,
        ),
        cryptoKey,
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError('decryptSync() is unsupported');
  }

  @override
  Future<Uint8List> encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) async {
    if (offset != 0) {
      throw ArgumentError.value(offset, 'offset', 'Should be 0');
    }
    if (nonce == null) {
      throw ArgumentError.notNull('nonce');
    }
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKey.bytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CTR',
          length: 8 * secretKey.bytes.length,
        ),
        true,
        ['encrypt'],
      ),
    );
    final counter = Uint8List.fromList(nonce.bytes.sublist(0, 16)).buffer;
    ByteData.view(counter)..setUint32(8, 0)..setUint32(12, 0);
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.encrypt(
        web_crypto.AesCtrParams(
          name: 'AES-CTR',
          counter: counter,
          length: 64,
        ),
        cryptoKey,
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }

  @override
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError('encryptSync() is unsupported');
  }
}

class WebAesGcmCipher extends Cipher {
  const WebAesGcmCipher();

  @override
  String get name => 'aesGcm';

  @override
  int get nonceLength => 16;

  @override
  SecretKeyGenerator get secretKeyGenerator => _aesKeyGenerator;

  @override
  Future<Uint8List> decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) async {
    if (offset != 0) {
      throw ArgumentError.value(offset, 'offset', 'Should be 0');
    }
    if (nonce == null) {
      throw ArgumentError.notNull('nonce');
    }
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKey.bytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-GCM',
          length: 8 * secretKey.bytes.length,
        ),
        true,
        ['decrypt'],
      ),
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.decrypt(
        web_crypto.AesGcmParams(
          name: 'AES-GCM',
          arrayBuffer: null,
          tagLength: 128,
          iv: Uint8List.fromList(nonce.bytes).buffer,
        ),
        cryptoKey,
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError('decryptSync() is unsupported');
  }

  @override
  Future<Uint8List> encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) async {
    if (offset != 0) {
      throw ArgumentError.value(offset, 'offset', 'Should be 0');
    }
    if (nonce == null) {
      throw ArgumentError.notNull('nonce');
    }
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKey.bytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-GCM',
          length: 8 * secretKey.bytes.length,
        ),
        true,
        ['encrypt'],
      ),
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.encrypt(
        web_crypto.AesGcmParams(
          name: 'AES-GCM',
          arrayBuffer: null,
          tagLength: 128,
          iv: Uint8List.fromList(nonce.bytes).buffer,
        ),
        cryptoKey,
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }

  @override
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError('encryptSync() is unsupported');
  }
}

class WebEcdh extends KeyExchangeAlgorithm {
  @override
  final String name;
  final String webCryptoNamedCurve;
  @override
  final KeyPairGenerator keyPairGenerator;
  final KeyExchangeAlgorithm polyfill;

  const WebEcdh({
    @required this.name,
    @required this.webCryptoNamedCurve,
    @required this.keyPairGenerator,
    @required this.polyfill,
  });

  @override
  Future<SecretKey> sharedSecret({
    PrivateKey localPrivateKey,
    PublicKey remotePublicKey,
  }) async {
    final privateBytes = localPrivateKey.bytes;
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
      web_crypto.subtle.importKey(
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
    if (polyfill == null) {
      throw UnsupportedError('sharedSecretSync() is unsupported');
    }
    return polyfill.sharedSecretSync(
      localPrivateKey: localPrivateKey,
      remotePublicKey: remotePublicKey,
    );
  }

  static String _base64UrlEncode(List<int> data) {
    var s = base64Url.encode(data);

    // Remove trailing '=' characters
    var length = s.length;
    while (s.startsWith('=', length - 1)) {
      length--;
    }

    return s.substring(0, length);
  }
}

class WebEcdsa extends SignatureAlgorithm {
  @override
  final String name;
  final String webCryptoNamedCurve;
  final String webCryptoHashName;
  @override
  final KeyPairGenerator keyPairGenerator;
  final SignatureAlgorithm polyfill;

  const WebEcdsa({
    @required this.name,
    @required this.webCryptoNamedCurve,
    @required this.webCryptoHashName,
    @required this.keyPairGenerator,
    @required this.polyfill,
  });

  @override
  Future<Signature> sign(List<int> input, KeyPair keyPair) async {
    final privateBytes = keyPair.privateKey.bytes;
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
      web_crypto.subtle.importKey(
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
    return polyfill.signSync(input, keyPair);
  }

  @override
  Future<bool> verify(List<int> input, Signature signature) async {
    final publicKeyBytes = signature.publicKey.bytes;
    final publicKeyJs = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
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
    return polyfill.verifySync(input, signature);
  }

  static String _base64UrlEncode(List<int> data) {
    var s = base64Url.encode(data);

    // Remove trailing '=' characters
    var length = s.length;
    while (s.startsWith('=', length - 1)) {
      length--;
    }

    return s.substring(0, length);
  }
}

class WebEcKeyPairGenerator extends KeyPairGenerator {
  @override
  final String name;
  final String webCryptoName;

  const WebEcKeyPairGenerator({
    @required this.name,
    @required this.webCryptoName,
  })  : assert(name != null),
        assert(webCryptoName != null);

  @override
  Future<KeyPair> generate() {
    // Generate key
    final promise = web_crypto.subtle.generateKey(
      web_crypto.EcdhParams(
        name: 'ECDH',
        namedCurve: webCryptoName,
      ),
      true,
      ['deriveBits'],
    );
    return js
        .promiseToFuture<web_crypto.CryptoKeyPair>(promise)
        .then((cryptoKeyPair) async {
      final privateKeyJwk = await js.promiseToFuture<web_crypto.Jwk>(
        web_crypto.subtle.exportKey('jwk', cryptoKeyPair.privateKey),
      );

      // Get private key.
      // There is no standard for raw private keys,
      // so we simply choose:
      //   d + x + y
      final privateKeyBytes = <int>[
        ..._base64UriDecode(privateKeyJwk.d),
        ..._base64UriDecode(privateKeyJwk.x),
        ..._base64UriDecode(privateKeyJwk.y),
      ];

      // Get public key.
      final publicByteBuffer = await js.promiseToFuture<ByteBuffer>(
        web_crypto.subtle.exportKey('raw', cryptoKeyPair.publicKey),
      );
      final publicKeyBytes = Uint8List.view(publicByteBuffer);

      return KeyPair(
        privateKey: PrivateKey(privateKeyBytes),
        publicKey: PublicKey(publicKeyBytes),
      );
    });
  }

  @override
  KeyPair generateSync() {
    throw UnsupportedError('newKeyPairSync() is unsupported');
  }

  static List<int> _base64UriDecode(String s) {
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
}

class WebHashAlgorithm extends HashAlgorithm {
  @override
  final String name;
  @override
  final hashLengthInBytes;
  final String webCryptoName;

  final HashAlgorithm polyfill;

  const WebHashAlgorithm({
    @required this.name,
    @required this.hashLengthInBytes,
    @required this.webCryptoName,
    @required this.polyfill,
  })  : assert(name != null),
        assert(hashLengthInBytes != null),
        assert(webCryptoName != null);

  @override
  HashSink newSink() {
    return polyfill.newSink();
  }
}

class WebSignatureAlgorithm extends SignatureAlgorithm {
  @override
  final String name;
  final String webCryptoName;
  @override
  final KeyPairGenerator keyPairGenerator;
  final SignatureAlgorithm polyfill;

  const WebSignatureAlgorithm({
    @required this.name,
    @required this.webCryptoName,
    @required this.keyPairGenerator,
    @required this.polyfill,
  })  : assert(name != null),
        assert(webCryptoName != null);

  @override
  Future<Signature> sign(List<int> input, KeyPair keyPair) {
    final promise = web_crypto.subtle.sign(
      webCryptoName,
      null,
      _jsArrayBufferFrom(input),
    );
    return js.promiseToFuture(promise).then((jsObj) {
      throw UnimplementedError();
    });
  }

  @override
  Signature signSync(List<int> input, KeyPair keyPair) {
    if (polyfill == null) {
      throw UnsupportedError('signSync() is unsupported');
    }
    return polyfill.signSync(input, keyPair);
  }

  @override
  Future<bool> verify(List<int> input, Signature signature) {
    final cryptoSignature = null;
    final promise = web_crypto.subtle.verify(
      webCryptoName,
      null,
      cryptoSignature,
      _jsArrayBufferFrom(input),
    );
    return js.promiseToFuture(promise).then((jsObj) {
      return jsObj;
    });
  }

  @override
  bool verifySync(List<int> input, Signature signature) {
    if (polyfill == null) {
      throw UnsupportedError('verifySync() is unsupported');
    }
    return polyfill.verifySync(input, signature);
  }
}
