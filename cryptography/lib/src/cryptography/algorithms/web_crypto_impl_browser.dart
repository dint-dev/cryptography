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

import 'dart:async';
import 'dart:convert';
import 'dart:js' as js;
import 'dart:js_util' as js;
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

import 'aes_impl.dart' as dart;
import 'web_crypto_bindings.dart' as web_crypto;

const Cipher webAesCbc = _WebAesCbcCipher();

const Cipher webAesCtr = _WebAesCtrCipher();

const Cipher webAesGcm = _WebAesGcmCipher();

const KeyExchangeAlgorithm webEcdhP256 = _WebEcdh(
  name: 'ecdhP256',
  webCryptoNamedCurve: 'P-256',
  publicKeyLength: 32,
  polyfill: null,
);

const KeyExchangeAlgorithm webEcdhP384 = _WebEcdh(
  name: 'ecdhP384',
  webCryptoNamedCurve: 'P-384',
  publicKeyLength: 48,
  polyfill: null,
);

const KeyExchangeAlgorithm webEcdhP521 = _WebEcdh(
  name: 'ecdhP521',
  webCryptoNamedCurve: 'P-521',
  publicKeyLength: 66,
  polyfill: null,
);

const SignatureAlgorithm webEcdsaP256Sha256 = _WebEcdsa(
  name: 'ecdsaP256Sha256',
  webCryptoNamedCurve: 'P-256',
  webCryptoHashName: 'SHA-256',
  publicKeyLength: 32,
  polyfill: null,
);

const SignatureAlgorithm webEcdsaP384Sha256 = _WebEcdsa(
  name: 'ecdsaP384Sha256',
  webCryptoNamedCurve: 'P-384',
  webCryptoHashName: 'SHA-256',
  publicKeyLength: 48,
  polyfill: null,
);

const SignatureAlgorithm webEcdsaP521Sha256 = _WebEcdsa(
  name: 'ecdsaP521Sha256',
  webCryptoNamedCurve: 'P-521',
  webCryptoHashName: 'SHA-256',
  publicKeyLength: 66,
  polyfill: null,
);

List<int> _base64UriDecode(String s) {
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

ByteBuffer _jsArrayBufferFrom(List<int> data) {
  return Uint8List.fromList(data).buffer;
}

Future<KeyPair> _newWebEcKeyPair(String curve) {
  // Generate key
  final promise = web_crypto.subtle.generateKey(
    web_crypto.EcdhParams(
      name: 'ECDH',
      namedCurve: curve,
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

class _WebAesCbcCipher extends Cipher {
  const _WebAesCbcCipher();

  @override
  int get secretKeyLength => 32;

  @override
  String get name => 'aesCbc';

  @override
  int get nonceLength => 16;

  @override
  Set<int> get secretKeyValidLengths => const <int>{16, 24, 32};

  @override
  Future<Uint8List> decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    if (aad != null) {
      throw ArgumentError.value(
        aad,
        'aad',
        'Must be null',
      );
    }
    ArgumentError.checkNotNull(nonce, 'nonce');
    if (nonce.bytes.length != 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be 16 bytes',
      );
    }
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be 0',
      );
    }
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CBC',
          length: 8 * secretKeyBytes.length,
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
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    return dart.aesCbc.decryptSync(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<List<int>> encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    if (aad != null) {
      throw ArgumentError.value(
        aad,
        'aad',
        'Must be null',
      );
    }
    ArgumentError.checkNotNull(nonce, 'nonce');
    if (nonce.bytes.length != 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be 16 bytes',
      );
    }
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be 0',
      );
    }
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CBC',
          length: 8 * secretKeyBytes.length,
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
  List<int> encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    return dart.aesCbc.encryptSync(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }
}

class _WebAesCtrCipher extends Cipher {
  const _WebAesCtrCipher();

  @override
  int get secretKeyLength => 32;

  @override
  String get name => 'aesCtr';

  @override
  int get nonceLength => 12;

  @override
  Set<int> get secretKeyValidLengths => const <int>{16, 24, 32};

  @override
  Future<Uint8List> decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    ArgumentError.checkNotNull(nonce, 'nonce');
    if (nonce.bytes.length > 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be at most 16 bytes',
      );
    }
    if (keyStreamIndex % 16 != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be a multiple of 16',
      );
    }
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CTR',
          length: 8 * secretKeyBytes.length,
        ),
        true,
        ['decrypt'],
      ),
    );
    var counterBytes = Uint8List(16);
    counterBytes.setAll(0, nonce.bytes);
    if (keyStreamIndex != 0) {
      counterBytes = Nonce(counterBytes).increment(keyStreamIndex ~/ 16).bytes;
    }
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.decrypt(
        web_crypto.AesCtrParams(
          name: 'AES-CTR',
          counter: counterBytes.buffer,
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
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    return dart.aesCtr.decryptSync(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<List<int>> encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    ArgumentError.checkNotNull(nonce, 'nonce');
    if (nonce.bytes.length > 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be at most 16 bytes',
      );
    }
    if (keyStreamIndex % 16 != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be a multiple of 16',
      );
    }
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CTR',
          length: 8 * secretKeyBytes.length,
        ),
        true,
        ['encrypt'],
      ),
    );
    var counterBytes = Uint8List(16);
    counterBytes.setAll(0, nonce.bytes);
    if (keyStreamIndex != 0) {
      counterBytes = Nonce(counterBytes).increment(keyStreamIndex ~/ 16).bytes;
    }
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.encrypt(
        web_crypto.AesCtrParams(
          name: 'AES-CTR',
          counter: counterBytes.buffer,
          length: 64,
        ),
        cryptoKey,
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }

  @override
  List<int> encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    return dart.aesCtr.encryptSync(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }
}

class _WebAesGcmCipher extends Cipher {
  const _WebAesGcmCipher();

  @override
  int get secretKeyLength => 32;

  @override
  String get name => 'aesGcm';

  @override
  int get nonceLength => 12;

  @override
  bool get isAuthenticated => true;

  @override
  Set<int> get secretKeyValidLengths => const <int>{16, 24, 32};

  @override
  Future<Uint8List> decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(
          keyStreamIndex, 'keyStreamIndex', 'Should be 0');
    }
    if (nonce == null) {
      throw ArgumentError.notNull('nonce');
    }
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-GCM',
          length: 8 * secretKeyBytes.length,
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
    Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    throw UnsupportedError('decryptSync() is unsupported');
  }

  @override
  Future<List<int>> encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(
          keyStreamIndex, 'keyStreamIndex', 'Should be 0');
    }
    if (nonce == null) {
      throw ArgumentError.notNull('nonce');
    }
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-GCM',
          length: 8 * secretKeyBytes.length,
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
  List<int> encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    throw UnsupportedError('encryptSync() is unsupported');
  }
}

class _WebEcdh extends KeyExchangeAlgorithm {
  @override
  final String name;
  final String webCryptoNamedCurve;
  @override
  final int publicKeyLength;
  final KeyExchangeAlgorithm polyfill;

  const _WebEcdh({
    @required this.name,
    @required this.webCryptoNamedCurve,
    @required this.publicKeyLength,
    @required this.polyfill,
  });

  @override
  Future<KeyPair> newKeyPair() {
    return _newWebEcKeyPair(webCryptoNamedCurve);
  }

  @override
  KeyPair newKeyPairSync() {
    throw UnsupportedError('This implementation only support newKeyPair()');
  }

  @override
  Future<SecretKey> sharedSecret({
    PrivateKey localPrivateKey,
    PublicKey remotePublicKey,
  }) async {
    final privateBytes = localPrivateKey.extractSync();
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

class _WebEcdsa extends SignatureAlgorithm {
  @override
  final String name;
  final String webCryptoNamedCurve;
  final String webCryptoHashName;
  @override
  final int publicKeyLength;
  final SignatureAlgorithm polyfill;

  const _WebEcdsa({
    @required this.name,
    @required this.webCryptoNamedCurve,
    @required this.webCryptoHashName,
    @required this.publicKeyLength,
    @required this.polyfill,
  });

  @override
  Future<KeyPair> newKeyPair() {
    return _newWebEcKeyPair(webCryptoNamedCurve);
  }

  @override
  KeyPair newKeyPairSync() {
    throw UnsupportedError('This implementation only support newKeyPair()');
  }

  @override
  Future<Signature> sign(List<int> input, KeyPair keyPair) async {
    final privateBytes = keyPair.privateKey.extractSync();
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
